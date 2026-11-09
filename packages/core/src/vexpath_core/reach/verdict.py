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


def _targets(graph: CallGraph, symbols: Sequence[VulnerableSymbol]) -> tuple[str, ...]:
    """Expand an advisory's symbols into the names the search can match.

    A class expands to its methods, because a fix touching a class changed its
    behaviour. A symbol absent from the graph is kept: it may still appear as
    the target of a direct call, which is evidence on its own.
    """
    expanded = list(expand_targets(graph, (symbol.symbol for symbol in symbols)))
    expanded.extend(symbol.symbol for symbol in symbols)
    return tuple(dict.fromkeys(expanded))


def _reached(
    status: ReachStatus,
    matched: tuple[str, ...],
    searched: tuple[str, ...],
    context: ReachabilityContext,
    symbols: Sequence[VulnerableSymbol],
) -> ReachabilityResult:
    path = context.result.path_to(matched[0], context.graph)
    via_dynamic = (
        any(step.edge_kind in {EdgeKind.DYNAMIC, EdgeKind.OPAQUE} for step in path)
        or status is ReachStatus.REACHABLE_POSSIBLE
    )

    return ReachabilityResult(
        status=status,
        confidence=_reachable_confidence(status, context, symbols),
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
        explanation=_reached_explanation(status, matched, path, context),
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
) -> str:
    symbol = matched[0]
    start = path[0].symbol if path else "an entry point"  # type: ignore[attr-defined]
    if status is ReachStatus.REACHABLE_CONFIRMED:
        return (
            f"{symbol} is called from {start}, through {len(path)} resolved "
            f"call(s). The vulnerable code can run."
        )
    return (
        f"{symbol} may be called from {start}, but every path found depends on a "
        f"call this analysis could not resolve precisely, such as dynamic "
        f"dispatch. Treat it as reachable until proven otherwise."
    )


def _unreachable_explanation(
    finding: Finding, symbols: Sequence[VulnerableSymbol], context: ReachabilityContext
) -> str:
    names = ", ".join(dict.fromkeys(symbol.symbol for symbol in symbols))
    return (
        f"{names} is not reachable from the {context.entry_points.count} entry "
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
    "MAX_PARSE_ERROR_RATIO",
    "ReachabilityContext",
    "apply",
    "decide",
    "mentioned_symbols",
]
