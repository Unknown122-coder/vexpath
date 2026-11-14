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
from vexpath_core.reach.verdict import (
    ReachabilityContext,
    apply,
    decide,
    import_roots,
    mentioned_symbols,
)

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
        import_names=import_roots(graph),
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


# --- Classes: reaching the body is not reaching the methods ----------------

CLASS_SYMBOL = "requests.sessions.Session"
SIBLING = "requests.sessions.Session.__init__"


def _class_graph(*, arrival: EdgeKind) -> CallGraph:
    """A project that reaches a dependency's class, and that class's methods.

    ``arrival`` is how the class itself is reached: by import, as any module
    that defines it reaches it, or by a resolved call, as a constructor does.
    """
    nodes = {
        "app.main": Node("app.main", SymbolKind.MODULE, file="app/main.py", line=1),
        "requests.sessions": Node(
            "requests.sessions",
            SymbolKind.MODULE,
            file="requests/sessions.py",
            line=1,
            package=PACKAGE,
        ),
        CLASS_SYMBOL: Node(
            CLASS_SYMBOL,
            SymbolKind.CLASS,
            file="requests/sessions.py",
            line=400,
            package=PACKAGE,
        ),
        SIBLING: Node(
            SIBLING, SymbolKind.METHOD, file="requests/sessions.py", line=405, package=PACKAGE
        ),
        TARGET: Node(
            TARGET, SymbolKind.METHOD, file="requests/sessions.py", line=700, package=PACKAGE
        ),
    }
    return CallGraph(
        nodes=nodes,
        edges={
            "app.main": (Edge("app.main", "requests.sessions", EdgeKind.IMPORT, 1),),
            "requests.sessions": (Edge("requests.sessions", CLASS_SYMBOL, arrival, 400),),
            # Constructing the class runs __init__, which the fix did not touch.
            CLASS_SYMBOL: (Edge(CLASS_SYMBOL, SIBLING, EdgeKind.STATIC, 405),),
        },
        quality=GraphQuality(call_sites=10, files_parsed=2),
    )


def test_a_class_reached_only_by_import_is_not_a_confirmation() -> None:
    """Found on real data, against nltk's CVE-2026-33236.

    Importing a module executes its class statements, so a class is reached by
    any code that imports its module. The class body running is not its
    methods running, and saying "the vulnerable code can run" on that basis
    overstates what was proven.
    """
    context = _context(_class_graph(arrival=EdgeKind.IMPORT))
    result = decide(
        _finding(),
        [
            _symbol(CLASS_SYMBOL, kind=SymbolKind.CLASS),
            _symbol(TARGET, kind=SymbolKind.METHOD),
        ],
        context,
    )

    assert result.status is ReachStatus.REACHABLE_POSSIBLE
    assert "runs the class body but not its methods" in result.explanation
    # Still reported, never cleared: the method may well be called through
    # something the analysis could not resolve.
    assert result.status.is_reachable
    assert not result.status.may_suppress


def test_a_class_reached_by_a_resolved_call_is_a_confirmation() -> None:
    """Constructing a class is not merely defining it."""
    context = _context(_class_graph(arrival=EdgeKind.STATIC))
    result = decide(
        _finding(),
        [_symbol(CLASS_SYMBOL, kind=SymbolKind.CLASS), _symbol(TARGET)],
        context,
    )
    assert result.status is ReachStatus.REACHABLE_CONFIRMED


def test_a_named_method_stops_its_siblings_counting_as_the_target() -> None:
    """Expanding a class to every method manufactures reachability.

    Measured on nltk: the expansion added 36 members, two of which run whenever
    the class is instantiated. A verdict built on those says the vulnerable
    code runs whenever any part of the class is used.
    """
    context = _context(_class_graph(arrival=EdgeKind.IMPORT))
    result = decide(
        _finding(),
        [
            _symbol(CLASS_SYMBOL, kind=SymbolKind.CLASS),
            _symbol(TARGET, kind=SymbolKind.METHOD),
        ],
        context,
    )
    # __init__ is reachable and belongs to the class, but the fix named a
    # different method, so it is not a target.
    assert SIBLING not in result.matched_symbols
    assert SIBLING not in result.searched_symbols


def test_a_class_named_alone_still_expands_to_its_methods() -> None:
    """With no finer target, the methods are the only way to arrive there."""
    context = _context(_class_graph(arrival=EdgeKind.IMPORT))
    result = decide(_finding(), [_symbol(CLASS_SYMBOL, kind=SymbolKind.CLASS)], context)
    # __init__ is reached by a resolved call, so this is a confirmation.
    assert result.status is ReachStatus.REACHABLE_CONFIRMED
    assert SIBLING in result.matched_symbols


def test_a_module_reached_by_import_is_a_possibility_not_a_confirmation() -> None:
    """Importing runs module-level code. That is reached, not confirmed.

    This asserted the opposite until 2026-11-13, on the reasoning that when a
    fix changed module-level code, importing it runs exactly that change --
    which is true. What it does not establish is that the vulnerability can be
    triggered: the fix changed a constant or a module-level statement, and
    running an assignment is not the same as running the code that reads it.

    The class-body case one branch above has made the same argument since M2:
    the class statement ran, which is not the same as its methods running. A
    module match was the louder version of the same overstatement, and across
    the PyPI corpus 136 of 3,028 advisory/package pairs rested on it alone.
    """
    graph = CallGraph(
        nodes={
            "app.main": Node("app.main", SymbolKind.MODULE, file="app/main.py", line=1),
            "requests.sessions": Node(
                "requests.sessions",
                SymbolKind.MODULE,
                file="requests/sessions.py",
                line=1,
                package=PACKAGE,
            ),
        },
        edges={"app.main": (Edge("app.main", "requests.sessions", EdgeKind.IMPORT, 1),)},
        quality=GraphQuality(call_sites=10, files_parsed=2),
    )
    result = decide(
        _finding(),
        [_symbol("requests.sessions", kind=SymbolKind.MODULE)],
        _context(graph),
    )
    assert result.status is ReachStatus.REACHABLE_POSSIBLE
    # And it says why in its own words, rather than borrowing the generic
    # possible-verdict wording about "something this analysis could not see":
    # here the analysis saw everything, and the module-level code does run.
    assert "runs when the package is imported" in result.explanation
    assert "depends on what reads the changed value" in result.explanation


def test_a_possible_verdict_does_not_invent_a_dynamic_edge() -> None:
    """The flag says what the path contains, not what the verdict is.

    ``via_dynamic_edges`` was forced true for every possible verdict, so a
    class or module reached by a plain import claimed its path went through
    dynamic dispatch. Anyone reading the evidence, or writing a policy on
    ``f.reach.via_dynamic_edges``, would have believed it.

    A possible verdict now justifies itself with ``reason`` instead, and the
    model requires one or the other -- so it still cannot be possible for no
    stated cause.
    """
    graph = CallGraph(
        nodes={
            "app.main": Node("app.main", SymbolKind.MODULE, file="app/main.py", line=1),
            "requests.sessions": Node(
                "requests.sessions",
                SymbolKind.MODULE,
                file="requests/sessions.py",
                line=1,
                package=PACKAGE,
            ),
        },
        edges={"app.main": (Edge("app.main", "requests.sessions", EdgeKind.IMPORT, 1),)},
        quality=GraphQuality(call_sites=10, files_parsed=2),
    )

    result = decide(
        _finding(),
        [_symbol("requests.sessions", kind=SymbolKind.MODULE)],
        _context(graph),
    )

    assert result.status is ReachStatus.REACHABLE_POSSIBLE
    # An import edge is neither dynamic nor opaque, and the result says so.
    assert result.via_dynamic_edges is False
    assert result.reason is ReachReason.MODULE_LEVEL_ONLY


def test_a_possible_verdict_still_cannot_be_unexplained() -> None:
    """Widening the invariant must not weaken it to nothing."""
    from vexpath_core.models.finding import ReachabilityResult

    with pytest.raises(ValueError, match="needs either a dynamic or opaque edge"):
        ReachabilityResult(
            status=ReachStatus.REACHABLE_POSSIBLE,
            confidence=Confidence.LOW,
            matched_symbols=("lib.danger",),
            via_dynamic_edges=False,
        )


# --- The advisory's name is not always this version's name ------------------
#
# Taken from a real scan. python-multipart renamed the package it installs
# from ``multipart`` to ``python_multipart``, so symbols extracted from its
# fix commits are rooted at the new name while 0.0.9 ships the same code under
# the old one. Eight findings on one project came back undecidable with the
# vulnerable method sitting in the graph the whole time.

DISTRIBUTION = "python-multipart"
#: What the corpus holds, extracted from a fix commit in the newer layout.
ADVISORY_SYMBOL = "python_multipart.multipart.MultipartParser._internal_write"
#: What 0.0.9 actually installs: the same code, a different root.
INSTALLED_SYMBOL = "multipart.multipart.MultipartParser._internal_write"


def _renamed_graph(*, reachable: bool) -> CallGraph:
    nodes = {
        "app.main": Node("app.main", SymbolKind.MODULE, file="app/main.py", line=1),
        "app.main.run": Node("app.main.run", SymbolKind.FUNCTION, file="app/main.py", line=4),
        INSTALLED_SYMBOL: Node(
            INSTALLED_SYMBOL,
            SymbolKind.METHOD,
            file="multipart/multipart.py",
            line=700,
            package=DISTRIBUTION,
        ),
    }
    edges: dict[str, tuple[Edge, ...]] = {
        "app.main": (Edge("app.main", "app.main.run", EdgeKind.IMPORT, 1),)
    }
    if reachable:
        edges["app.main.run"] = (Edge("app.main.run", INSTALLED_SYMBOL, EdgeKind.STATIC, 5),)
    return CallGraph(nodes=nodes, edges=edges, quality=GraphQuality(call_sites=10, files_parsed=2))


def _renamed_symbol(symbol: str = ADVISORY_SYMBOL) -> VulnerableSymbol:
    return VulnerableSymbol(
        advisory_id="CVE-2026-53539",
        ecosystem="PyPI",
        package_name=DISTRIBUTION,
        symbol=symbol,
        kind=SymbolKind.METHOD,
        source=SymbolSource.FIX_COMMIT,
        confidence=Confidence.HIGH,
    )


def _renamed_context(graph: CallGraph) -> ReachabilityContext:
    return _context(graph, analysed=frozenset({DISTRIBUTION}))


def test_a_renamed_import_package_is_recognised() -> None:
    """The finding this was built for: decidable instead of undecidable."""
    graph = _renamed_graph(reachable=True)
    result = decide(_finding(name=DISTRIBUTION), [_renamed_symbol()], _renamed_context(graph))

    assert result.status is ReachStatus.REACHABLE_CONFIRMED
    assert result.matched_symbols == (INSTALLED_SYMBOL,)
    # Reported under the name the reader can find in their own environment.
    assert result.searched_symbols == (INSTALLED_SYMBOL,)


def test_a_renamed_symbol_says_the_name_was_changed() -> None:
    """Otherwise the report and the advisory disagree for no visible reason."""
    graph = _renamed_graph(reachable=True)
    result = decide(_finding(name=DISTRIBUTION), [_renamed_symbol()], _renamed_context(graph))

    assert "python_multipart in the advisory, multipart here" in result.explanation


def test_a_renamed_symbol_does_not_claim_full_confidence() -> None:
    """The match is strong evidence, not something the advisory said.

    The tail of the name matching exactly, against a definition that really
    exists, is most of the way to certain -- but which root belongs to which
    version is this tool's inference, so a verdict resting on it says medium.
    """
    graph = _renamed_graph(reachable=True)
    result = decide(_finding(name=DISTRIBUTION), [_renamed_symbol()], _renamed_context(graph))

    assert result.confidence is Confidence.MEDIUM


def test_a_renamed_symbol_that_is_not_called_is_cleared() -> None:
    """The risky direction, so it is asserted rather than assumed.

    A rewrite makes a clearance possible where there was none, which is the
    one outcome that can be wrong in the user's favour. It is allowed here
    because the symbol was found and searched for: the package was traversed
    and nothing calls it.
    """
    graph = _renamed_graph(reachable=False)
    finding = apply(_finding(name=DISTRIBUTION), [_renamed_symbol()], _renamed_context(graph))

    assert finding.reach is not None
    assert finding.reach.status is ReachStatus.UNREACHABLE
    assert finding.verdict is Verdict.NOT_AFFECTED
    assert "different import name" in finding.reach.explanation


def test_a_rewrite_never_invents_a_target() -> None:
    """A candidate is accepted only when the graph already defines it.

    Substituting roots blindly would let any advisory match any package that
    happens to share a module path, which would manufacture reachable
    verdicts. A symbol that exists under no provided root stays undecided.
    """
    graph = _renamed_graph(reachable=True)
    gone = _renamed_symbol("python_multipart.multipart.MultipartParser.deleted_in_this_version")
    result = decide(_finding(name=DISTRIBUTION), [gone], _renamed_context(graph))

    assert result.status is ReachStatus.SYMBOLS_UNKNOWN
    assert result.reason is ReachReason.SYMBOLS_NOT_IN_VERSION
    assert result.searched_symbols == (gone.symbol,)
    # No single cause is asserted, because the message used to blame a
    # function rename for what was an import-package rename.
    assert "renamed, moved to another module, or did not exist yet" in result.explanation


def test_a_name_that_already_matches_is_left_alone() -> None:
    """No note, and no lowered confidence, when nothing was rewritten."""
    graph = _renamed_graph(reachable=True)
    result = decide(
        _finding(name=DISTRIBUTION), [_renamed_symbol(INSTALLED_SYMBOL)], _renamed_context(graph)
    )

    assert result.status is ReachStatus.REACHABLE_CONFIRMED
    assert result.confidence is Confidence.HIGH
    assert "import name" not in result.explanation


def test_a_package_with_no_graph_is_not_rewritten() -> None:
    """Nothing to check a candidate against, so nothing is attempted.

    The verdict is the same admitted unknown it was before: an absence of
    paths through code that was never traversed proves nothing, and a rewrite
    cannot change that.
    """
    graph = _renamed_graph(reachable=False)
    context = _context(graph, analysed=frozenset())
    result = decide(_finding(name=DISTRIBUTION), [_renamed_symbol()], context)

    assert result.status is ReachStatus.SYMBOLS_UNKNOWN
    assert result.reason is ReachReason.PACKAGE_NOT_ANALYSED


def test_import_roots_ignores_first_party_code() -> None:
    """A project's own modules are not a distribution's import names."""
    roots = import_roots(_renamed_graph(reachable=True))

    assert roots == {DISTRIBUTION: frozenset({"multipart"})}


def _package_root_graph(*, roots: tuple[str, ...] = ("multipart",)) -> CallGraph:
    """A graph where the distribution's module root is imported by the project."""
    nodes = {
        "app.main": Node("app.main", SymbolKind.MODULE, file="app/main.py", line=1),
        "app.main.run": Node("app.main.run", SymbolKind.FUNCTION, file="app/main.py", line=4),
    }
    for name in roots:
        nodes[name] = Node(
            name, SymbolKind.MODULE, file=f"{name}/__init__.py", line=1, package=DISTRIBUTION
        )
    return CallGraph(
        nodes=nodes,
        edges={
            "app.main": (
                Edge("app.main", "app.main.run", EdgeKind.IMPORT, 1),
                Edge("app.main", roots[0], EdgeKind.IMPORT, 2),
            )
        },
        quality=GraphQuality(call_sites=10, files_parsed=2),
    )


def test_a_renamed_package_root_is_matched_rather_than_cleared() -> None:
    """A module-level fix is recorded as the bare package name.

    Leaving that name alone meant it was never searched for, and a finding
    could then be *cleared* because nothing reached a symbol nobody looked
    for. An unearned clearance is the one failure this whole module exists to
    prevent, so the bare name is rewritten like any other.
    """
    graph = _package_root_graph()
    symbol = _renamed_symbol("python_multipart")
    result = decide(
        _finding(name=DISTRIBUTION),
        [symbol.model_copy(update={"kind": SymbolKind.MODULE})],
        _renamed_context(graph),
    )

    assert result.searched_symbols == ("multipart",)
    assert result.status is ReachStatus.REACHABLE_POSSIBLE
    assert result.reason is ReachReason.MODULE_LEVEL_ONLY
    assert "different import name" in result.explanation


def test_an_ambiguous_package_root_is_not_guessed() -> None:
    """Two importable roots and no tail to tell them apart.

    The dotted case is decided by the rest of the name matching a definition
    that exists. A bare name has no such evidence, so with more than one
    candidate the honest answer is the admitted unknown.
    """
    graph = _package_root_graph(roots=("multipart", "multipart_extras"))
    symbol = _renamed_symbol("python_multipart")
    result = decide(
        _finding(name=DISTRIBUTION),
        [symbol.model_copy(update={"kind": SymbolKind.MODULE})],
        _renamed_context(graph),
    )

    assert result.status is ReachStatus.SYMBOLS_UNKNOWN
    assert result.reason is ReachReason.SYMBOLS_NOT_IN_VERSION
    assert result.searched_symbols == ("python_multipart",)
