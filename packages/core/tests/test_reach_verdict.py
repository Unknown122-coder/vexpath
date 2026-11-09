"""The verdict rules.

Almost every test here asserts a refusal. This module is where the product's
central promise lives, so the cases that must *not* produce a clean verdict are
spelled out individually rather than left to emerge from the benchmark.
"""

from __future__ import annotations

import pytest

from vexpath_core.enums import (
    ComponentScope,
    Confidence,
    EdgeKind,
    EntryPointSource,
    ReachReason,
    ReachStatus,
    SymbolKind,
    SymbolSource,
    Verdict,
    VexJustification,
)
from vexpath_core.models.advisory import VulnerableSymbol
from vexpath_core.models.finding import AdvisoryRef, ComponentRef, EntryPointInfo, Finding
from vexpath_core.reach.graph import CallGraph, Edge, GraphQuality, Node, link, search
from vexpath_core.reach.verdict import ReachabilityContext, apply, decide, mentioned_symbols

PACKAGE = "requests"
TARGET = "requests.sessions.Session.send"


def _graph(
    *,
    reachable: bool,
    quality: GraphQuality | None = None,
    edge_kind: EdgeKind = EdgeKind.STATIC,
    include_target: bool = True,
) -> CallGraph:
    nodes = {
        "app.main": Node("app.main", SymbolKind.MODULE, file="app/main.py", line=1),
        "app.main.run": Node("app.main.run", SymbolKind.FUNCTION, file="app/main.py", line=4),
    }
    if include_target:
        nodes[TARGET] = Node(
            TARGET,
            SymbolKind.METHOD,
            file="requests/sessions.py",
            line=700,
            package=PACKAGE,
        )
    edges: dict[str, tuple[Edge, ...]] = {
        "app.main": (Edge("app.main", "app.main.run", EdgeKind.IMPORT, 1),)
    }
    if reachable and include_target:
        edges["app.main.run"] = (Edge("app.main.run", TARGET, edge_kind, 5),)
    return CallGraph(
        nodes=nodes,
        edges=edges,
        quality=quality or GraphQuality(call_sites=10, files_parsed=2),
    )


def _context(
    graph: CallGraph,
    *,
    analysed: frozenset[str] = frozenset({PACKAGE}),
    source: EntryPointSource = EntryPointSource.CONFIG,
) -> ReachabilityContext:
    entry_points = ("app.main", "app.main.run")
    result = search(graph, entry_points)
    return ReachabilityContext(
        graph=graph,
        result=result,
        entry_points=EntryPointInfo(source=source, count=2, items=entry_points),
        analysed_packages=analysed,
        mentioned=mentioned_symbols(graph),
    )


def _finding(ecosystem: str = "PyPI", name: str = PACKAGE) -> Finding:
    return Finding(
        id="01",
        advisory=AdvisoryRef(id="CVE-2024-35195"),
        component=ComponentRef(
            purl=f"pkg:pypi/{name}@2.31.0",
            ecosystem=ecosystem,
            name=name,
            version="2.31.0",
            direct=True,
            scope=ComponentScope.RUNTIME,
        ),
        verdict=Verdict.AFFECTED,
    )


def _symbol(
    symbol: str = TARGET,
    *,
    confidence: Confidence = Confidence.HIGH,
    source: SymbolSource = SymbolSource.FIX_COMMIT,
    kind: SymbolKind = SymbolKind.METHOD,
) -> VulnerableSymbol:
    return VulnerableSymbol(
        advisory_id="CVE-2024-35195",
        ecosystem="PyPI",
        package_name=PACKAGE,
        symbol=symbol,
        kind=kind,
        source=source,
        confidence=confidence,
    )


# --- Refusals --------------------------------------------------------------


def test_a_dependency_without_a_graph_is_never_cleared() -> None:
    """An absence of paths through code you cannot see proves nothing.

    This is the most dangerous mistake available: the component is present, no
    path was found, and reporting that as safe would be wrong whenever the
    dependency calls its own vulnerable code internally.
    """
    graph = _graph(reachable=False)
    context = _context(graph, analysed=frozenset())
    result = decide(_finding(), [_symbol()], context)

    assert result.status is ReachStatus.SYMBOLS_UNKNOWN
    assert result.reason is ReachReason.PACKAGE_NOT_ANALYSED
    assert not result.status.may_suppress
    assert "does not prove" in result.explanation


def test_an_advisory_without_symbols_is_never_cleared() -> None:
    graph = _graph(reachable=False)
    result = decide(_finding(), [], _context(graph))
    assert result.status is ReachStatus.SYMBOLS_UNKNOWN
    assert result.reason is ReachReason.NO_FIX_COMMIT
    assert not result.status.may_suppress


def test_a_non_python_component_is_never_cleared() -> None:
    graph = _graph(reachable=False)
    result = decide(_finding(ecosystem="npm", name="lodash"), [_symbol()], _context(graph))
    assert result.reason is ReachReason.ECOSYSTEM_UNSUPPORTED
    assert not result.status.may_suppress


def test_too_many_parse_failures_block_a_clearance() -> None:
    graph = _graph(
        reachable=False,
        quality=GraphQuality(call_sites=10, files_parsed=50, files_failed=10),
    )
    result = decide(_finding(), [_symbol()], _context(graph))
    assert result.status is ReachStatus.GRAPH_INCOMPLETE
    assert result.reason is ReachReason.PARSE_ERRORS
    assert not result.status.may_suppress


def test_a_symbol_absent_from_this_version_is_not_a_clearance() -> None:
    # The fix touched a function that does not exist in the installed version,
    # usually a rename. Absence of the symbol is not absence of the bug.
    graph = _graph(reachable=False, include_target=False)
    result = decide(_finding(), [_symbol()], _context(graph))
    assert result.status is ReachStatus.SYMBOLS_UNKNOWN
    assert result.reason is ReachReason.SYMBOLS_NOT_IN_VERSION
    assert not result.status.may_suppress


# --- The clearance that is allowed ----------------------------------------


def test_a_complete_search_that_finds_nothing_does_clear_the_finding() -> None:
    graph = _graph(reachable=False)
    finding = apply(_finding(), [_symbol()], _context(graph))

    assert finding.verdict is Verdict.NOT_AFFECTED
    assert finding.justification is VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
    assert finding.reach is not None
    assert finding.reach.status is ReachStatus.UNREACHABLE
    assert finding.reach.searched_symbols == (TARGET,)
    assert "no call path leads to" in finding.reach.explanation


def test_guessed_entry_points_do_not_block_a_clearance() -> None:
    """The guess is every public function, a superset of the real entry points.

    Finding no path from a superset is stronger evidence than finding none from
    a precise set, so it strengthens an unreachable verdict rather than
    weakening it.
    """
    graph = _graph(reachable=False)
    context = _context(graph, source=EntryPointSource.FALLBACK_PUBLIC)
    result = decide(_finding(), [_symbol()], context)
    assert result.status is ReachStatus.UNREACHABLE
    assert result.confidence is Confidence.HIGH


def test_an_unresolved_graph_lowers_confidence_in_a_clearance() -> None:
    graph = _graph(
        reachable=False,
        quality=GraphQuality(call_sites=100, unresolved_call_sites=50, files_parsed=10),
    )
    result = decide(_finding(), [_symbol()], _context(graph))
    assert result.status is ReachStatus.UNREACHABLE
    assert result.confidence is Confidence.LOW


# --- Reachable verdicts ----------------------------------------------------


def test_a_resolved_path_is_confirmed_and_blocks() -> None:
    graph = _graph(reachable=True)
    finding = apply(_finding(), [_symbol()], _context(graph))

    assert finding.verdict is Verdict.AFFECTED
    assert finding.justification is None
    assert finding.reach is not None
    assert finding.reach.status is ReachStatus.REACHABLE_CONFIRMED
    assert finding.reach.confidence is Confidence.HIGH
    assert not finding.reach.via_dynamic_edges
    assert [step.symbol for step in finding.reach.shortest_path][-1] == TARGET


def test_a_guessed_path_is_possible_and_still_blocks() -> None:
    graph = _graph(reachable=True, edge_kind=EdgeKind.DYNAMIC)
    finding = apply(_finding(), [_symbol()], _context(graph))

    assert finding.reach is not None
    assert finding.reach.status is ReachStatus.REACHABLE_POSSIBLE
    assert finding.reach.confidence is Confidence.LOW
    assert finding.reach.via_dynamic_edges
    # Uncertainty blocks. It never clears.
    assert finding.verdict is Verdict.AFFECTED


def test_weak_symbol_provenance_lowers_confidence() -> None:
    graph = _graph(reachable=True)
    weak = _symbol(confidence=Confidence.LOW, source=SymbolSource.TAG_DIFF)
    result = decide(_finding(), [weak], _context(graph))
    assert result.status is ReachStatus.REACHABLE_CONFIRMED
    assert result.confidence is Confidence.LOW


def test_guessed_entry_points_lower_confidence_in_a_reachable_verdict() -> None:
    # The path may begin at a function nothing ever calls.
    graph = _graph(reachable=True)
    context = _context(graph, source=EntryPointSource.FALLBACK_PUBLIC)
    result = decide(_finding(), [_symbol()], context)
    assert result.status is ReachStatus.REACHABLE_CONFIRMED
    assert result.confidence is Confidence.MEDIUM


def test_a_class_symbol_expands_to_its_methods() -> None:
    """A fix touching a class changed its behaviour, so its methods count."""
    nodes = {
        "app.main": Node("app.main", SymbolKind.MODULE),
        "app.main.run": Node("app.main.run", SymbolKind.FUNCTION),
        "requests.sessions.Session": Node(
            "requests.sessions.Session", SymbolKind.CLASS, package=PACKAGE
        ),
        TARGET: Node(TARGET, SymbolKind.METHOD, package=PACKAGE),
    }
    edges = {
        "app.main": (Edge("app.main", "app.main.run", EdgeKind.IMPORT),),
        "app.main.run": (Edge("app.main.run", TARGET, EdgeKind.STATIC),),
    }
    graph = CallGraph(nodes=nodes, edges=edges, quality=GraphQuality(call_sites=5, files_parsed=1))
    symbol = _symbol("requests.sessions.Session", kind=SymbolKind.CLASS)
    result = decide(_finding(), [symbol], _context(graph))

    assert result.status is ReachStatus.REACHABLE_CONFIRMED
    assert TARGET in result.matched_symbols


def test_every_result_carries_the_entry_points_it_used() -> None:
    graph = _graph(reachable=True)
    result = decide(_finding(), [_symbol()], _context(graph))
    assert result.entry_points is not None
    assert result.entry_points.count == 2


# --- The model refuses to represent a forbidden conclusion ----------------


def test_the_model_rejects_a_clearance_the_verdict_layer_did_not_earn() -> None:
    """Defence in depth: even a bug here cannot ship a false clearance.

    The verdict layer decides, and the model independently refuses any
    combination that would clear a finding without proof.
    """
    from pydantic import ValidationError

    graph = _graph(reachable=True)
    reachable = decide(_finding(), [_symbol()], _context(graph))

    # Constructing the forbidden combination directly, as a buggy future
    # caller might, must fail rather than produce a cleared finding.
    with pytest.raises(ValidationError, match="only 'unreachable' may suppress"):
        Finding(
            id="01",
            advisory=AdvisoryRef(id="CVE-2024-35195"),
            component=_finding().component,
            verdict=Verdict.NOT_AFFECTED,
            justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            reach=reachable,
        )


def test_linking_merges_quality_so_statistics_stay_honest() -> None:
    first = CallGraph(quality=GraphQuality(call_sites=10, unresolved_call_sites=1, files_parsed=2))
    second = CallGraph(
        package=PACKAGE,
        quality=GraphQuality(call_sites=90, unresolved_call_sites=9, files_parsed=8),
    )
    merged = link([first, second])
    assert merged.quality.call_sites == 100
    assert merged.quality.unresolved_call_sites == 10
    assert merged.quality.unresolved_ratio == pytest.approx(0.10)
