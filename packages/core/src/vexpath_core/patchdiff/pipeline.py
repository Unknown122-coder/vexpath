"""Run symbol extraction for one advisory, end to end.

Resolve the fix, fetch the diff, map paths to module names, name the symbols.
The stages stay separate underneath so each can be tested on its own; this is
the one call a worker needs.

What comes back is always an answer, never an exception for the ordinary
failures. An advisory with no fix reference, a repository that cannot be
fetched, a commit that touched no Python: each is a fact about that advisory
that the corpus should record, not an error that should stop a sync of
thousands.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vexpath_core.enums import Confidence, SymbolsStatus
from vexpath_core.models.advisory import Advisory, VulnerableSymbol
from vexpath_core.patchdiff.extract import extract
from vexpath_core.patchdiff.fetch import CommitSource, FetchError
from vexpath_core.patchdiff.layout import layout_for
from vexpath_core.patchdiff.references import (
    FixReference,
    UnresolvableFixError,
    resolve,
)


@dataclass(frozen=True, slots=True)
class PatchDiffResult:
    """What extraction concluded for one advisory."""

    advisory_id: str
    status: SymbolsStatus
    symbols: tuple[VulnerableSymbol, ...] = ()
    reference: FixReference | None = None
    #: Why the status is what it is, in plain language. Shown by
    #: ``vexpath advisory show`` so a reader can see why a finding stayed under
    #: investigation rather than being told only that it did.
    detail: str = ""
    notes: tuple[str, ...] = field(default=())

    @property
    def succeeded(self) -> bool:
        return self.status is SymbolsStatus.EXTRACTED

    @property
    def best_confidence(self) -> Confidence | None:
        if not self.symbols:
            return None
        return max((symbol.confidence for symbol in self.symbols), key=lambda value: value.rank)


def extract_for_advisory(
    advisory: Advisory, source: CommitSource, *, ecosystem: str = "PyPI"
) -> PatchDiffResult:
    """Extract vulnerable symbols for one advisory.

    Args:
        advisory: The advisory to work on.
        source: Where to fetch the commit from.
        ecosystem: Which of the advisory's affected packages to extract for.
            Only one ecosystem is handled per call, because symbol names are
            ecosystem-specific.
    """
    if advisory.is_malicious_package:
        # There is no fix to diff, and reachability is the wrong question:
        # installing malware runs it.
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            detail=(
                "This is a malicious-package record, not a vulnerability. There is "
                "no fix to diff, and its presence alone is the finding."
            ),
        )

    packages = [package for package in advisory.affected if package.ecosystem == ecosystem]
    if not packages:
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            detail=f"The advisory affects no {ecosystem} package.",
        )

    try:
        reference = resolve(advisory)
    except UnresolvableFixError as exc:
        return PatchDiffResult(advisory_id=advisory.id, status=SymbolsStatus.NONE, detail=str(exc))

    if reference.needs_resolution:
        # A pull request or release tag still needs a lookup to become a
        # commit. Recording the reference means the next run can start there
        # rather than resolving it again.
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.PENDING,
            reference=reference,
            detail=(
                f"The fix is identified by a {reference.tier.value.replace('_', ' ')} "
                f"rather than a commit, which has to be resolved before the diff "
                f"can be read."
            ),
        )

    try:
        commit_diff = source.fetch(reference)
    except FetchError as exc:
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.FAILED,
            reference=reference,
            detail=f"Could not fetch {reference.commit} from {reference.repository}: {exc}",
        )

    if not commit_diff.files:
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            reference=reference,
            detail=(
                f"Commit {reference.commit[:12] if reference.commit else '?'} changed no "
                f"Python source outside tests. The fix may be in data, in another "
                f"language, or in the build."
            ),
            notes=commit_diff.notes,
        )

    collected: list[VulnerableSymbol] = []
    failures: list[str] = []
    refactor = False

    for package in packages:
        layout = layout_for(
            package.name,
            pyproject=commit_diff.pyproject,
            setup_cfg=commit_diff.setup_cfg,
        )
        symbols, report = extract(
            advisory.id,
            ecosystem,
            package.name,
            list(commit_diff.files),
            layout,
            reference_confidence=reference.confidence,
            commit=reference.commit,
        )
        collected.extend(symbols)
        failures.extend(report.failures)
        refactor = refactor or report.looks_like_refactor

    if not collected:
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.NONE,
            reference=reference,
            detail=(
                "The commit's changed files could not be mapped to importable "
                "modules of the affected package, so no symbol could be named."
            ),
            notes=(*commit_diff.notes, *failures),
        )

    detail = (
        f"Extracted {len(collected)} symbol(s) from commit "
        f"{reference.commit[:12] if reference.commit else '?'}."
    )
    if refactor:
        detail += (
            " The commit touches enough symbols to look like a refactor, so every "
            "symbol is recorded at low confidence and the advisory is worth a "
            "human look."
        )

    return PatchDiffResult(
        advisory_id=advisory.id,
        status=SymbolsStatus.EXTRACTED,
        symbols=tuple(collected),
        reference=reference,
        detail=detail,
        notes=(*commit_diff.notes, *failures),
    )


def with_symbols(advisory: Advisory, result: PatchDiffResult) -> Advisory:
    """Return the advisory carrying what extraction found.

    Curated symbols are preserved and take precedence: a human reviewed them,
    and a later extraction run must not quietly replace that judgement.
    """
    from vexpath_core.enums import SymbolSource

    curated = tuple(symbol for symbol in advisory.symbols if symbol.source is SymbolSource.CURATED)
    curated_names = {(symbol.package_name, symbol.symbol) for symbol in curated}
    extracted = tuple(
        symbol
        for symbol in result.symbols
        if (symbol.package_name, symbol.symbol) not in curated_names
    )

    status = result.status
    if curated and status is not SymbolsStatus.EXTRACTED:
        # A curated symbol is itself a successful extraction, whatever the
        # commit lookup did.
        status = SymbolsStatus.EXTRACTED

    return advisory.model_copy(update={"symbols": (*curated, *extracted), "symbols_status": status})


__all__ = ["PatchDiffResult", "extract_for_advisory", "with_symbols"]
