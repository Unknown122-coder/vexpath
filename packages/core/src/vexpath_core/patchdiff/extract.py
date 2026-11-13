"""Map a commit's changed lines to the symbols that contain them.

This is the step that produces what reachability searches for. Given a file
before and after a fix, and the lines the fix touched, it names the functions,
methods, classes or modules those lines belong to.

Both versions of the file are examined, for a reason that is easy to miss: a
fix that deletes a vulnerable function leaves no trace in the post-image, and
the deleted name is exactly the one installed versions still contain. Reading
only the new file would lose precisely the symbol that matters.

Confidence reflects how directly the fix touched each symbol:

- **high**, when changed lines sit inside a function body. That is where the
  vulnerable logic was, or where the guard was added.
- **medium**, when only a signature, a decorator or a docstring changed, or
  when the symbol came from a reference weaker than an exact commit.
- **low**, when the commit is large enough to look like a refactor, or the
  module path had to be guessed.

Erring toward naming too many symbols is deliberate. An extra symbol makes a
finding look reachable when it is not, which is noise. A missing symbol makes a
reachable finding look clear, which is the failure this project refuses.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Literal

from vexpath_core.enums import Confidence, SymbolKind, SymbolSource
from vexpath_core.models.advisory import VulnerableSymbol
from vexpath_core.patchdiff.layout import PackageLayout
from vexpath_core.patchdiff.unidiff import FileDiff

#: Above this many symbols from one commit, the commit is a refactor or a
#: release merge rather than a fix. Every symbol is kept, because dropping
#: them could hide the real one, but all of them are marked low confidence and
#: the advisory is flagged for review.
REFACTOR_SYMBOL_THRESHOLD = 25


@dataclass(frozen=True, slots=True)
class ExtractedSymbol:
    """One symbol a fix commit touched, before it becomes a model object."""

    symbol: str
    kind: SymbolKind
    confidence: Confidence
    file_path: str
    #: Which side of the diff it was found on. A symbol found only in the
    #: pre-image was deleted by the fix, and is still present in every
    #: affected version, which is what makes it worth keeping.
    side: Literal["post", "pre"]


@dataclass(slots=True)
class ExtractionReport:
    """Everything one commit yielded, and what went wrong."""

    symbols: list[ExtractedSymbol] = field(default_factory=list)
    #: Files that could not be parsed, with the reason.
    failures: list[str] = field(default_factory=list)
    #: Files skipped because they are not part of the package.
    unmapped: list[str] = field(default_factory=list)
    #: True when the commit touched enough symbols to look like a refactor.
    looks_like_refactor: bool = False

    @property
    def is_empty(self) -> bool:
        return not self.symbols


def extract_from_file(
    file_diff: FileDiff,
    layout: PackageLayout,
    *,
    post_source: str | None,
    pre_source: str | None,
    reference_confidence: Confidence = Confidence.HIGH,
) -> tuple[list[ExtractedSymbol], list[str]]:
    """Extract symbols from one file's change.

    Returns the symbols found and any parse failures. A file that fails to
    parse is reported rather than raised: one unparsable file in a commit must
    not discard the rest of it.
    """
    mapped = layout.module_for(file_diff.path)
    if mapped is None:
        return [], []
    module, path_confidence = mapped

    if path_confidence is Confidence.LOW:
        # The path did not anchor on any import name this package provides, so
        # whatever it defines belongs to a different package. Recording it
        # anyway would attribute a symbol to the wrong distribution, and a
        # symbol in the wrong place can drive a verdict: searched for in this
        # package's graph it would never be found, and "not found" is one step
        # from "cleared". Better to extract nothing and say so.
        #
        # This happens in practice. An advisory for one distribution often
        # links the fix commit of a separate project that the distribution
        # depends on or vendors.
        return [], []

    found: list[ExtractedSymbol] = []
    failures: list[str] = []

    for side, source, lines in (
        ("post", post_source, file_diff.added_lines),
        ("pre", pre_source, file_diff.removed_lines),
    ):
        if not source or not lines:
            continue
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError) as exc:
            failures.append(f"{file_diff.path} ({side}): {type(exc).__name__}: {exc}")
            continue

        for symbol, kind, body_touched in _symbols_at(tree, module, lines):
            found.append(
                ExtractedSymbol(
                    symbol=symbol,
                    kind=kind,
                    confidence=_combine(
                        reference_confidence, path_confidence, body_touched=body_touched
                    ),
                    file_path=file_diff.path,
                    side=side,  # type: ignore[arg-type]
                )
            )

    if file_diff.truncated:
        found = [
            symbol
            if symbol.confidence is Confidence.LOW
            else ExtractedSymbol(
                symbol=symbol.symbol,
                kind=symbol.kind,
                confidence=Confidence.LOW,
                file_path=symbol.file_path,
                side=symbol.side,
            )
            for symbol in found
        ]

    return found, failures


def _symbols_at(
    tree: ast.Module, module: str, lines: list[int]
) -> list[tuple[str, SymbolKind, bool]]:
    """Find the innermost definition containing each changed line.

    Returns the qualified name, its kind, and whether the change was inside the
    body rather than on the signature or a decorator. A line belonging to no
    definition is module-level code, which means importing the module runs the
    change, so the module itself is the symbol.
    """
    results: dict[str, tuple[SymbolKind, bool]] = {}
    targets = set(lines)
    if not targets:
        return []

    def visit(node: ast.AST, prefix: str, owner: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                qualname = f"{prefix}.{child.name}"
                _record(child, qualname, SymbolKind.CLASS, results, targets)
                visit(child, qualname, qualname)
            elif isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                qualname = f"{prefix}.{child.name}"
                kind = SymbolKind.METHOD if owner else SymbolKind.FUNCTION
                _record(child, qualname, kind, results, targets)
                # A nested function's changes belong to its parent as far as
                # reachability is concerned: the parent is what gets called.
                visit(child, qualname, owner)

    visit(tree, module, None)

    # Lines inside a definition are attributed to it. Anything left over is
    # module-level code, and importing the module runs it -- but only if it is
    # code. An import statement and a docstring also "run" on import and
    # neither can carry a vulnerability, so a fix that adds an import or
    # reflows a docstring must not mark the whole module as the vulnerable
    # symbol. It did: because a module match is treated as confirmed
    # reachability, every project importing the package was told its
    # vulnerable code can run, on the evidence of a changed docstring.
    covered = _covered_lines(tree) | _inert_lines(tree)
    if any(line not in covered for line in targets):
        results.setdefault(module, (SymbolKind.MODULE, True))

    return [(symbol, kind, body) for symbol, (kind, body) in results.items()]


def _record(
    node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
    qualname: str,
    kind: SymbolKind,
    results: dict[str, tuple[SymbolKind, bool]],
    targets: set[int],
) -> None:
    """Record a definition if a changed line falls inside it."""
    start = min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)])
    end = node.end_lineno or node.lineno
    touched = [line for line in targets if start <= line <= end]
    if not touched:
        return

    body_start = node.body[0].lineno if node.body else node.lineno
    in_body = any(line >= body_start for line in touched)

    existing = results.get(qualname)
    if existing is None or (in_body and not existing[1]):
        results[qualname] = (kind, in_body)


def _covered_lines(tree: ast.Module) -> set[int]:
    """Every line belonging to a top-level definition."""
    covered: set[int] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            start = min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)])
            covered.update(range(start, (node.end_lineno or node.lineno) + 1))
    return covered


def _inert_lines(tree: ast.Module) -> set[int]:
    """Module-level lines that run on import but cannot be a vulnerability.

    Imports and the module docstring. Both execute when the module is
    imported, which is why they were counted as module-level code, and
    neither can be the thing an advisory is about: an import binds a name and
    a docstring is a string.

    Module-level *constants* are deliberately not in here. A changed regular
    expression is a plausible fix for a denial of service, so an assignment
    stays evidence even though it only binds a value.
    """
    inert: set[int] = set()
    for index, node in enumerate(tree.body):
        is_import = isinstance(node, ast.Import | ast.ImportFrom)
        is_docstring = (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
        if is_import or is_docstring:
            inert.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return inert


def _combine(reference: Confidence, path: Confidence, *, body_touched: bool) -> Confidence:
    """Combine every source of doubt into one confidence.

    The weakest link wins, and a change that only touched a signature or a
    decorator cannot be better than medium however good the reference was.
    """
    ranked = [reference, path]
    if not body_touched:
        ranked.append(Confidence.MEDIUM)
    return min(ranked, key=lambda confidence: confidence.rank)


def _belongs_to_package(path: str, layout: PackageLayout) -> bool:
    """Whether a changed path is part of the package being extracted for.

    A path that maps to nothing, or only at low confidence, is not. Reporting
    it as unmapped is how a caller learns that a commit was fetched and read
    but had nothing to say about this package.
    """
    mapped = layout.module_for(path)
    return mapped is not None and mapped[1] is not Confidence.LOW


def extract(
    advisory_id: str,
    ecosystem: str,
    package: str,
    files: list[tuple[FileDiff, str | None, str | None]],
    layout: PackageLayout,
    *,
    reference_confidence: Confidence = Confidence.HIGH,
    commit: str | None = None,
    source: SymbolSource = SymbolSource.FIX_COMMIT,
) -> tuple[tuple[VulnerableSymbol, ...], ExtractionReport]:
    """Extract every vulnerable symbol a commit's diff reveals.

    Args:
        advisory_id: Advisory these symbols belong to.
        ecosystem: Ecosystem of the affected package.
        package: Affected package name, already normalised.
        files: Each changed file with its post-image and pre-image sources.
            Either source may be None, for an added or deleted file.
        layout: How this repository's paths map to module names.
        reference_confidence: How trustworthy the fix reference was.
        commit: Commit the symbols came from, recorded for provenance.
        source: How these symbols were obtained. A release-range diff is
            ``TAG_DIFF`` rather than ``FIX_COMMIT``, and the difference is
            not cosmetic: one names the functions a fix changed, the other
            the functions a release changed.
    """
    report = ExtractionReport()

    for file_diff, post_source, pre_source in files:
        found, failures = extract_from_file(
            file_diff,
            layout,
            post_source=post_source,
            pre_source=pre_source,
            reference_confidence=reference_confidence,
        )
        report.failures.extend(failures)
        if not found and not _belongs_to_package(file_diff.path, layout):
            report.unmapped.append(file_diff.path)
        report.symbols.extend(found)

    # Collapse duplicates, keeping the strongest reading of each symbol. The
    # same function often appears on both sides of a diff.
    strongest: dict[str, ExtractedSymbol] = {}
    for symbol in report.symbols:
        existing = strongest.get(symbol.symbol)
        if existing is None or symbol.confidence.rank > existing.confidence.rank:
            strongest[symbol.symbol] = symbol
    report.symbols = sorted(strongest.values(), key=lambda item: item.symbol)

    if len(report.symbols) > REFACTOR_SYMBOL_THRESHOLD:
        # A commit this broad is a refactor or a release merge. Every symbol is
        # kept, because dropping them could hide the real one, but none of them
        # is trustworthy on its own.
        report.looks_like_refactor = True
        report.symbols = [
            ExtractedSymbol(
                symbol=item.symbol,
                kind=item.kind,
                confidence=Confidence.LOW,
                file_path=item.file_path,
                side=item.side,
            )
            for item in report.symbols
        ]

    symbols = tuple(
        VulnerableSymbol(
            advisory_id=advisory_id,
            ecosystem=ecosystem,
            package_name=package,
            symbol=item.symbol,
            kind=item.kind,
            source=source,
            confidence=item.confidence,
            file_path=item.file_path,
            fix_commit=commit,
        )
        for item in report.symbols
    )
    return symbols, report


__all__ = [
    "REFACTOR_SYMBOL_THRESHOLD",
    "ExtractedSymbol",
    "ExtractionReport",
    "extract",
    "extract_from_file",
]
