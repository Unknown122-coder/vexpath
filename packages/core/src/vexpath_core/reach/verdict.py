"""Turn a search result into a verdict, with its evidence.

This module is where the product's central promise is enforced, so its rules
are written out rather than left implicit in control flow.

**Only a complete search over a complete graph may conclude "unreachable".**
Three things can each make an absence of paths meaningless, and each produces
an admitted unknown instead of a clean verdict:

- The dependency's own call graph was not available. We can still see a direct
  call to a vulnerable symbol, so "reachable" remains sound, but we cannot see
  the dependency's internals, so "no path exists" is not a claim we are
  entitled to make.
- The advisory does not say which symbols are vulnerable, so there is nothing
  to search for.
- Too much of the project's own source failed to parse.

**Inferred entry points cut one way only.** When the starting points are
guessed, the guess is the set of every public function, which is a superset of
reality. Finding no path from a superset is stronger evidence, not weaker, so
it does not block an unreachable verdict. It does lower confidence in a
*reachable* verdict, because the path may begin somewhere never actually
invoked.

**A malicious package is not a reachability question.** Installing it runs it.
Those findings never enter this module.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from vexpath_core.enums import (
    Confidence,
    EdgeKind,
    EntryPointSource,
    ReachReason,
    ReachStatus,
    SymbolKind,
    Verdict,
    VexJustification,
    supports_reachability,
)
from vexpath_core.models.advisory import VulnerableSymbol
from vexpath_core.models.finding import (
    CallPathStep,
    EntryPointInfo,
    Finding,
    GraphStats,
    ReachabilityResult,
)
from vexpath_core.reach.graph import CallGraph, SearchResult, expand_targets

#: Above this share of unparsable first-party files, the graph is too
#: incomplete for an absence of paths to mean anything.
MAX_PARSE_ERROR_RATIO = 0.05


@dataclass(frozen=True, slots=True)
class ReachabilityContext:
    """Everything a verdict needs besides the finding itself."""

    graph: CallGraph
    result: SearchResult
    entry_points: EntryPointInfo
    #: Packages whose own call graph is linked into the search. A component
    #: outside this set cannot be cleared, only confirmed or admitted unknown.
    analysed_packages: frozenset[str] = frozenset()
    #: Every symbol the analysis saw referenced, whether or not it is defined
    #: in a linked graph. A call to a vulnerable symbol counts even when the
    #: dependency's internals are invisible.
    mentioned: frozenset[str] = frozenset()

    def has_graph_for(self, package: str) -> bool:
        return package in self.analysed_packages


def decide(
    finding: Finding,
    symbols: Sequence[VulnerableSymbol],
    context: ReachabilityContext,
) -> ReachabilityResult:
    """Decide whether a finding's vulnerable code can run."""
    if not supports_reachability(finding.component.ecosystem):
        return _unknown(
            ReachReason.ECOSYSTEM_UNSUPPORTED,
            context,
            explanation=(
                f"Reachability analysis is not implemented for "
                f"{finding.component.ecosystem}, so whether this code can "
                f"execute is unknown rather than cleared."
            ),
        )

    if not symbols:
        return _unknown(
            ReachReason.NO_FIX_COMMIT,
            context,
            explanation=(
                "The advisory does not say which functions its fix changed, so "
                "there is nothing to search for. Reachability is unknown."
            ),
        )

    quality = context.graph.quality
    if quality.parse_error_ratio > MAX_PARSE_ERROR_RATIO:
        return _unknown(
            ReachReason.PARSE_ERRORS,
            context,
            explanation=(
                f"{quality.files_failed} of "
                f"{quality.files_failed + quality.files_parsed} source files could "
                f"not be parsed, so the call graph is too incomplete to trust."
            ),
            searched=tuple(symbol.symbol for symbol in symbols),
        )

    targets = _targets(context.graph, symbols)
    certain = tuple(symbol for symbol in targets if symbol in context.result.certain)
    possible = tuple(
        symbol
        for symbol in targets
        if symbol not in context.result.certain and symbol in context.result.possible
    )

    if certain and _only_class_bodies(certain, context):
        # Every certain match is a class arrived at purely by import. The class
        # statement ran, which is not the same as its methods running, so this
        # is a possibility rather than a confirmation.
        return _reached(
            ReachStatus.REACHABLE_POSSIBLE,
            certain,
            targets,
            context,
            symbols,
            reason=_CLASS_BODY_ONLY,
            cause=ReachReason.CLASS_BODY_ONLY,
        )
    if certain and _only_module_level(certain, context):
        # Module-level code runs when the package is imported, so this is
        # reached. What it is not is confirmed: the fix changed a constant or
        # a module-level statement rather than a function, and running an
        # assignment is not the same as running the code that reads it. The
        # same argument the class-body case makes one line above.
        return _reached(
            ReachStatus.REACHABLE_POSSIBLE,
            certain,
            targets,
            context,
            symbols,
            explanation=_module_level_explanation(certain[0], context),
            cause=ReachReason.MODULE_LEVEL_ONLY,
        )
    if certain:
        return _reached(ReachStatus.REACHABLE_CONFIRMED, certain, targets, context, symbols)
    if possible:
        return _reached(ReachStatus.REACHABLE_POSSIBLE, possible, targets, context, symbols)

    # Nothing was reached. Whether that means anything depends on whether the
    # search could see inside the package at all.
    package = finding.component.name
    if not context.has_graph_for(package):
        return _unknown(
            ReachReason.PACKAGE_NOT_ANALYSED,
            context,
            explanation=(
                f"No call graph was available for {package} "
                f"{finding.component.version}, so its internals could not be "
                f"traversed. Nothing in this project calls the vulnerable "
                f"symbols directly, but that does not prove they cannot run."
            ),
            searched=tuple(symbol.symbol for symbol in symbols),
        )

    known = [symbol for symbol in targets if symbol in context.mentioned]
    if not known:
        return _unknown(
            ReachReason.SYMBOLS_NOT_IN_VERSION,
            context,
            explanation=(
                f"None of the vulnerable symbols exist in {package} "
                f"{finding.component.version}, which usually means they were "
                f"renamed. Reachability cannot be decided against a symbol that "
                f"is not there."
            ),
            searched=tuple(symbol.symbol for symbol in symbols),
        )

    return ReachabilityResult(
        status=ReachStatus.UNREACHABLE,
        confidence=_unreachable_confidence(context),
        searched_symbols=tuple(dict.fromkeys(symbol.symbol for symbol in symbols)),
        entry_points=context.entry_points,
        graph_stats=_stats(context),
        explanation=_unreachable_explanation(finding, symbols, context),
    )


#: Why a class-only match is not a confirmation. Stated once, because it is
#: shown to a reader and must not drift between the status and the text.
_CLASS_BODY_ONLY = (
    "every path to it reaches a class definition by import, which runs the "
    "class body but not its methods"
)


def _only_module_level(matched: Sequence[str], context: ReachabilityContext) -> bool:
    """True when every match is a module rather than something callable.

    A module is recorded as the vulnerable symbol when the fix changed code
    outside any definition: a constant, a module-level statement. Importing
    the package runs that, which is why it counts as reached at all -- but
    "the assignment ran" is weaker than "the vulnerable function was called",
    and reporting both as ``reachable_confirmed`` gave them equal weight.

    Measured when this was introduced: 136 of 3,028 advisory/package pairs in
    the PyPI corpus rested on module-level evidence alone, all of them
    reported as confirmed.
    """
    for symbol in matched:
        node = context.graph.nodes.get(symbol)
        if node is None or node.kind is not SymbolKind.MODULE:
            return False
    return True


def _module_level_explanation(symbol: str, context: ReachabilityContext) -> str:
    """Say what import-time execution does and does not establish.

    Deliberately not the generic possible-verdict wording, which says the
    outcome "depends on something this analysis could not see". Here the
    analysis saw everything: the module-level code definitely runs. What is
    unknown is whether the behaviour the advisory describes can be triggered,
    which depends on code that uses the changed value.
    """
    del context
    return (
        f"The fix changed module-level code in {symbol}, which runs when the "
        f"package is imported -- so it does run. No vulnerable function was "
        f"matched, though, so whether the problem can actually be triggered "
        f"depends on what reads the changed value. Treat it as reachable "
        f"until proven otherwise."
    )


def _only_class_bodies(matched: Sequence[str], context: ReachabilityContext) -> bool:
    """True when every match is a class arrived at only through imports.

    Importing a module executes its class statements, so a class is reachable
    from any code that imports its module. That is real execution, but it is
    the class body, not the methods inside it. An advisory whose fix changed a
    method also names the enclosing class, and without this check a one-line
    application that merely imports the package would be told its vulnerable
    code can run.

    A module target is deliberately not treated this way: when a fix changed
    module-level code, importing the module does run exactly that code.
    """
    for symbol in matched:
        node = context.graph.nodes.get(symbol)
        if node is None or node.kind is not SymbolKind.CLASS:
            return False
        path = context.result.path_to(symbol, context.graph)
        # The first step is the entry point and has no incoming edge.
        if any(step.edge_kind is not EdgeKind.IMPORT for step in path[1:]):
            return False
    return True


def _targets(graph: CallGraph, symbols: Sequence[VulnerableSymbol]) -> tuple[str, ...]:
    """Expand an advisory's symbols into the names the search can match.

    A class expands to its methods only when the advisory names no method
    inside it. When the fix touched a class body and nothing finer, its methods
    are the only way to arrive at that change, so they are the targets. When
    the advisory does name a method, that method is the target and its siblings
    are not: measured on nltk's CVE-2026-33236, expanding the class added 36
    members, two of which run whenever the class is instantiated, and a verdict
    built on those says the vulnerable code runs whenever any part of the class
    is used.

    A symbol absent from the graph is kept: it may still appear as the target
    of a direct call, which is evidence on its own.
    """
    named = {symbol.symbol for symbol in symbols}
    # Classes the advisory already describes through one of their members.
    pinned = {
        parent for symbol in named if (parent := symbol.rpartition(".")[0]) and parent in named
    }

    expanded = [
        candidate
        for candidate in expand_targets(graph, (symbol.symbol for symbol in symbols))
        if candidate in named or candidate.rpartition(".")[0] not in pinned
    ]
    expanded.extend(named)
    return tuple(dict.fromkeys(expanded))


def _reached(
    status: ReachStatus,
    matched: tuple[str, ...],
    searched: tuple[str, ...],
    context: ReachabilityContext,
    symbols: Sequence[VulnerableSymbol],
    *,
    reason: str | None = None,
    explanation: str | None = None,
    cause: ReachReason | None = None,
) -> ReachabilityResult:
    path = context.result.path_to(matched[0], context.graph)
    # Only what the path actually contains. It used to be forced true for
    # every possible verdict, which made a class reached by a plain import
    # claim it went through dynamic dispatch.
    via_dynamic = any(step.edge_kind in {EdgeKind.DYNAMIC, EdgeKind.OPAQUE} for step in path)

    return ReachabilityResult(
        status=status,
        confidence=_reachable_confidence(status, context, symbols),
        reason=cause,
        matched_symbols=matched,
        searched_symbols=tuple(dict.fromkeys(symbol.symbol for symbol in symbols)),
        shortest_path=tuple(
            CallPathStep(
                symbol=step.symbol,
                file=step.file,
                line=step.line,
                edge_kind=step.edge_kind,
            )
            for step in path
        ),
        path_count=len(matched),
        via_dynamic_edges=via_dynamic,
        entry_points=context.entry_points,
        graph_stats=_stats(context),
        explanation=(
            explanation
            if explanation is not None
            else _reached_explanation(status, matched, path, context, reason=reason)
        ),
    )


def _unknown(
    reason: ReachReason,
    context: ReachabilityContext,
    *,
    explanation: str,
    searched: tuple[str, ...] = (),
) -> ReachabilityResult:
    """Build an admitted unknown.

    Deliberately never ``unreachable``: every caller of this helper has a
    reason it could not decide, and a reason to doubt is not a clearance.
    """
    status = (
        ReachStatus.GRAPH_INCOMPLETE
        if reason in {ReachReason.PARSE_ERRORS, ReachReason.ENTRY_POINTS_UNKNOWN}
        else ReachStatus.SYMBOLS_UNKNOWN
    )
    return ReachabilityResult(
        status=status,
        confidence=Confidence.LOW,
        reason=reason,
        searched_symbols=searched,
        entry_points=context.entry_points,
        graph_stats=_stats(context),
        explanation=explanation,
    )


def _reachable_confidence(
    status: ReachStatus, context: ReachabilityContext, symbols: Sequence[VulnerableSymbol]
) -> Confidence:
    """How much to trust a reachable verdict.

    Lowered by a guessed path, by weak symbol provenance, and by guessed entry
    points, since the path may start at a function nothing ever calls.
    """
    if status is ReachStatus.REACHABLE_POSSIBLE:
        return Confidence.LOW

    weakest_symbol = min(
        (symbol.confidence for symbol in symbols),
        key=lambda value: value.rank,
        default=Confidence.LOW,
    )
    if weakest_symbol is Confidence.LOW:
        return Confidence.LOW
    if context.entry_points.source is EntryPointSource.FALLBACK_PUBLIC:
        return Confidence.MEDIUM
    if weakest_symbol is Confidence.MEDIUM:
        return Confidence.MEDIUM
    return Confidence.HIGH


def _unreachable_confidence(context: ReachabilityContext) -> Confidence:
    """How much to trust an unreachable verdict.

    Guessed entry points do not reduce it. The guess is every public function,
    a superset of the real starting points, so finding no path from it is
    stronger evidence than finding none from a precise set. What does reduce
    it is a graph full of calls the analysis could not resolve.
    """
    unresolved = context.graph.quality.unresolved_ratio
    if unresolved > 0.40:
        return Confidence.LOW
    if unresolved > 0.15:
        return Confidence.MEDIUM
    return Confidence.HIGH


def _stats(context: ReachabilityContext) -> GraphStats:
    quality = context.graph.quality
    first_party = sum(1 for node in context.graph.nodes.values() if node.is_first_party)
    return GraphStats(
        first_party_nodes=first_party,
        first_party_edges=context.graph.edge_count,
        linked_packages=len(context.analysed_packages),
        unresolved_call_ratio=round(quality.unresolved_ratio, 4),
        parse_error_files=quality.files_failed,
        parse_error_ratio=round(quality.parse_error_ratio, 4),
    )


def _reached_explanation(
    status: ReachStatus,
    matched: tuple[str, ...],
    path: Sequence[object],
    context: ReachabilityContext,
    *,
    reason: str | None = None,
) -> str:
    """Describe a reachable verdict in the terms a reader checks it in.

    The count is of calls, not of path steps: a path of five symbols is four
    calls, and claiming five invites a reader who counts to distrust the whole
    report. A path of one symbol is no calls at all, which means the vulnerable
    code is itself a starting point.
    """
    symbol = matched[0]
    start = path[0].symbol if path else "an entry point"  # type: ignore[attr-defined]
    calls = max(len(path) - 1, 0)

    if status is ReachStatus.REACHABLE_CONFIRMED:
        if calls == 0:
            return (
                f"{symbol} is itself an entry point of this project, so the "
                f"vulnerable code runs without being called from anywhere."
            )
        return (
            f"{symbol} is called from {start}, through {calls} resolved "
            f"call(s). The vulnerable code can run."
        )

    if reason is not None:
        return (
            f"{symbol} is reached from {start}, but {reason}. Whether the "
            f"changed code runs depends on something this analysis could not "
            f"see, so treat it as reachable until proven otherwise."
        )
    if calls == 0:
        return (
            f"{symbol} is itself an entry point of this project, but reaching it "
            f"depends on a call this analysis could not resolve precisely. Treat "
            f"it as reachable until proven otherwise."
        )
    return (
        f"{symbol} may be called from {start}, but every path found depends on a "
        f"call this analysis could not resolve precisely, such as dynamic "
        f"dispatch. Treat it as reachable until proven otherwise."
    )


#: Symbols named in a one-sentence explanation before it stops listing and
#: starts counting. A fix can touch eighty definitions, and a sentence holding
#: all of them is one nobody reads. The full list travels in
#: ``searched_symbols``, where a reader can see it without it being in the way.
MAX_NAMED_SYMBOLS = 3


def _unreachable_explanation(
    finding: Finding, symbols: Sequence[VulnerableSymbol], context: ReachabilityContext
) -> str:
    unique = list(dict.fromkeys(symbol.symbol for symbol in symbols))
    named = ", ".join(unique[:MAX_NAMED_SYMBOLS])
    subject = (
        f"{named} and {len(unique) - MAX_NAMED_SYMBOLS} other symbol(s) are"
        if len(unique) > MAX_NAMED_SYMBOLS
        else f"{named} {'are' if len(unique) > 1 else 'is'}"
    )
    return (
        f"{subject} not reachable from the {context.entry_points.count} entry "
        f"point(s) of this project. {finding.component.name} "
        f"{finding.component.version} is present and was traversed, but no call "
        f"path leads to the code the fix changed."
    )


def apply(
    finding: Finding,
    symbols: Sequence[VulnerableSymbol],
    context: ReachabilityContext,
) -> Finding:
    """Return the finding with its reachability result and final verdict.

    The verdict mapping is the one place a finding can become
    ``not_affected``, and it happens only on a proven unreachable result. The
    model refuses any other combination, so a mistake here fails loudly rather
    than shipping a false clearance.
    """
    result = decide(finding, symbols, context)

    if result.status is ReachStatus.UNREACHABLE:
        return finding.model_copy(
            update={
                "reach": result,
                "verdict": Verdict.NOT_AFFECTED,
                "justification": VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            }
        )

    if result.status.is_reachable:
        return finding.model_copy(
            update={"reach": result, "verdict": Verdict.AFFECTED, "justification": None}
        )

    return finding.model_copy(
        update={
            "reach": result,
            "verdict": Verdict.UNDER_INVESTIGATION,
            "justification": None,
        }
    )


def mentioned_symbols(graph: CallGraph) -> frozenset[str]:
    """Every symbol the graph defines or references.

    A referenced symbol that is not defined anywhere is a call into a package
    whose graph is absent. Knowing the difference between "referenced but
    unreached" and "never seen at all" is what separates an unreachable verdict
    from an admission that the symbol is not in this version.
    """
    seen = set(graph.nodes)
    for targets in graph.edges.values():
        seen.update(edge.target for edge in targets)
    return frozenset(seen)


__all__ = [
    "MAX_NAMED_SYMBOLS",
    "MAX_PARSE_ERROR_RATIO",
    "ReachabilityContext",
    "apply",
    "decide",
    "mentioned_symbols",
]
