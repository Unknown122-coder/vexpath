"""Graph structures and the reachability search.

The search answers two questions separately: what is certainly reachable and
what might be. Nearly everything here checks that the separation holds, because
collapsing it would either overstate certainty or hide real findings.
"""

from __future__ import annotations

import pytest

from vexpath_core.enums import EdgeKind, SymbolKind
from vexpath_core.reach.graph import (
    BUILDER_VERSION,
    CallGraph,
    Edge,
    GraphQuality,
    Node,
    expand_targets,
    link,
    matched_symbols,
    search,
)


def _graph(*edges: tuple[str, str, EdgeKind]) -> CallGraph:
    symbols = {symbol for source, target, _ in edges for symbol in (source, target)}
    nodes = {
        symbol: Node(
            symbol,
            SymbolKind.METHOD
            if symbol.split(".")[-1][0].islower() and "." in symbol
            else SymbolKind.MODULE,
            file=f"{symbol.split('.')[0]}.py",
            line=1,
        )
        for symbol in symbols
    }
    adjacency: dict[str, list[Edge]] = {}
    for source, target, kind in edges:
        adjacency.setdefault(source, []).append(Edge(source, target, kind, 1))
    return CallGraph(
        nodes=nodes,
        edges={source: tuple(items) for source, items in adjacency.items()},
    )


# --- Certain and possible --------------------------------------------------


def test_a_resolved_path_is_certain() -> None:
    graph = _graph(("a.run", "b.step", EdgeKind.STATIC), ("b.step", "c.target", EdgeKind.STATIC))
    result = search(graph, ["a.run"])
    assert "c.target" in result.certain
    assert result.status_of("c.target") == "certain"


def test_a_guessed_hop_makes_the_rest_only_possible() -> None:
    graph = _graph(("a.run", "b.step", EdgeKind.DYNAMIC), ("b.step", "c.target", EdgeKind.STATIC))
    result = search(graph, ["a.run"])
    assert "c.target" in result.possible
    assert "c.target" not in result.certain
    assert result.status_of("c.target") == "possible"


def test_an_import_edge_counts_as_certain() -> None:
    # Importing a module runs its top-level code; there is nothing uncertain
    # about that.
    graph = _graph(("a", "b", EdgeKind.IMPORT))
    assert "b" in search(graph, ["a"]).certain


def test_an_opaque_edge_is_never_certain() -> None:
    graph = _graph(("a.run", "b.target", EdgeKind.OPAQUE))
    result = search(graph, ["a.run"])
    assert "b.target" in result.possible
    assert "b.target" not in result.certain


def test_certain_is_always_a_subset_of_possible() -> None:
    graph = _graph(
        ("a.run", "b.step", EdgeKind.STATIC),
        ("a.run", "c.step", EdgeKind.DYNAMIC),
        ("b.step", "d.target", EdgeKind.STATIC),
    )
    result = search(graph, ["a.run"])
    assert result.certain <= result.possible


def test_a_certain_route_wins_over_a_guessed_one() -> None:
    # Two routes to the same symbol: the verdict should rest on the real one.
    graph = _graph(
        ("a.run", "b.step", EdgeKind.DYNAMIC),
        ("b.step", "z.target", EdgeKind.STATIC),
        ("a.run", "z.target", EdgeKind.STATIC),
    )
    result = search(graph, ["a.run"])
    assert "z.target" in result.certain


def test_nothing_is_reached_without_an_entry_point() -> None:
    graph = _graph(("a.run", "b.target", EdgeKind.STATIC))
    result = search(graph, [])
    assert result.possible == frozenset()
    assert result.entry_points == ()


def test_an_entry_point_absent_from_the_graph_is_dropped() -> None:
    # A stale configuration entry must not look like it contributed.
    graph = _graph(("a.run", "b.target", EdgeKind.STATIC))
    result = search(graph, ["a.run", "nonexistent.symbol"])
    assert result.entry_points == ("a.run",)


def test_a_cycle_does_not_hang_the_search() -> None:
    graph = _graph(
        ("a.run", "b.step", EdgeKind.STATIC),
        ("b.step", "a.run", EdgeKind.STATIC),
        ("b.step", "c.target", EdgeKind.STATIC),
    )
    assert "c.target" in search(graph, ["a.run"]).certain


def test_a_dangling_target_is_still_reached() -> None:
    """A direct call to a symbol is evidence even without that package's graph."""
    graph = CallGraph(
        nodes={"a.run": Node("a.run", SymbolKind.FUNCTION)},
        edges={"a.run": (Edge("a.run", "faraway.vulnerable", EdgeKind.STATIC),)},
    )
    assert "faraway.vulnerable" in search(graph, ["a.run"]).certain


# --- Evidence --------------------------------------------------------------


def test_the_path_runs_from_the_entry_point_to_the_target() -> None:
    graph = _graph(("a.run", "b.step", EdgeKind.STATIC), ("b.step", "c.target", EdgeKind.STATIC))
    result = search(graph, ["a.run"])
    path = result.path_to("c.target", graph)
    assert [step.symbol for step in path] == ["a.run", "b.step", "c.target"]
    assert path[0].file == "a.py"


def test_the_path_prefers_the_certain_route() -> None:
    graph = _graph(
        ("a.run", "slow.step", EdgeKind.DYNAMIC),
        ("slow.step", "z.target", EdgeKind.STATIC),
        ("a.run", "z.target", EdgeKind.STATIC),
    )
    result = search(graph, ["a.run"])
    path = result.path_to("z.target", graph)
    # The evidence shown matches the verdict given.
    assert [step.symbol for step in path] == ["a.run", "z.target"]
    assert all(step.edge_kind is EdgeKind.STATIC for step in path)


def test_an_unreached_symbol_has_no_path() -> None:
    graph = _graph(("a.run", "b.step", EdgeKind.STATIC))
    assert search(graph, ["a.run"]).path_to("nowhere.at.all", graph) == ()


def test_the_edge_kind_of_each_hop_is_recorded() -> None:
    graph = _graph(("a.run", "b.step", EdgeKind.STATIC), ("b.step", "c.target", EdgeKind.DYNAMIC))
    result = search(graph, ["a.run"])
    path = result.path_to("c.target", graph)
    assert path[-1].edge_kind is EdgeKind.DYNAMIC


# --- Linking ---------------------------------------------------------------


def test_linking_is_a_union() -> None:
    first = _graph(("a.run", "b.step", EdgeKind.STATIC))
    second = _graph(("b.step", "c.target", EdgeKind.STATIC))
    merged = link([first, second])
    assert "c.target" in search(merged, ["a.run"]).certain


def test_linking_combines_entry_points_without_duplicates() -> None:
    first = CallGraph(nodes={"a": Node("a", SymbolKind.MODULE)}, entry_points=("a",))
    second = CallGraph(nodes={"a": Node("a", SymbolKind.MODULE)}, entry_points=("a",))
    assert link([first, second]).entry_points == ("a",)


def test_linking_an_empty_list_yields_an_empty_graph() -> None:
    merged = link([])
    assert len(merged) == 0
    assert merged.edge_count == 0


# --- Target expansion ------------------------------------------------------


def test_a_class_expands_to_its_methods() -> None:
    graph = CallGraph(
        nodes={
            "pkg.Thing": Node("pkg.Thing", SymbolKind.CLASS),
            "pkg.Thing.alpha": Node("pkg.Thing.alpha", SymbolKind.METHOD),
            "pkg.Thing.beta": Node("pkg.Thing.beta", SymbolKind.METHOD),
            "pkg.Other.alpha": Node("pkg.Other.alpha", SymbolKind.METHOD),
        }
    )
    expanded = set(expand_targets(graph, ["pkg.Thing"]))
    assert {"pkg.Thing", "pkg.Thing.alpha", "pkg.Thing.beta"} <= expanded
    assert "pkg.Other.alpha" not in expanded


def test_an_unknown_target_expands_to_nothing() -> None:
    assert list(expand_targets(CallGraph(), ["nowhere"])) == []


def test_matched_symbols_separates_certain_from_possible() -> None:
    graph = _graph(
        ("a.run", "b.certain", EdgeKind.STATIC),
        ("a.run", "c.possible", EdgeKind.DYNAMIC),
    )
    result = search(graph, ["a.run"])
    certain, possible = matched_symbols(result, ["b.certain", "c.possible"], graph)
    assert certain == ("b.certain",)
    assert possible == ("c.possible",)


# --- Quality ---------------------------------------------------------------


def test_quality_ratios_are_computed_not_stored() -> None:
    quality = GraphQuality(
        call_sites=200, unresolved_call_sites=50, files_parsed=18, files_failed=2
    )
    assert quality.unresolved_ratio == pytest.approx(0.25)
    assert quality.parse_error_ratio == pytest.approx(0.10)


def test_quality_ratios_handle_an_empty_graph() -> None:
    quality = GraphQuality()
    assert quality.unresolved_ratio == 0.0
    assert quality.parse_error_ratio == 0.0


def test_merging_quality_caps_the_recorded_errors() -> None:
    # Diagnosis needs examples, not every one of them.
    left = GraphQuality(parse_errors=tuple(f"a{index}" for index in range(15)))
    right = GraphQuality(parse_errors=tuple(f"b{index}" for index in range(15)))
    assert len(left.merge(right).parse_errors) == 20


def test_a_graph_records_the_builder_version_that_made_it() -> None:
    assert CallGraph().builder_version == BUILDER_VERSION


def test_first_party_nodes_are_distinguishable() -> None:
    graph = CallGraph(
        nodes={
            "app": Node("app", SymbolKind.MODULE),
            "lib": Node("lib", SymbolKind.MODULE, package="lib"),
        }
    )
    assert graph.nodes["app"].is_first_party
    assert not graph.nodes["lib"].is_first_party
    assert graph.symbols_in_package("lib") == ("lib",)
