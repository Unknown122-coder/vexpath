"""The reachability benchmark.

Every fixture repository declares the verdict it must receive, and this runs
the real pipeline against each one: build the project's graph, build a graph per
vendored dependency, link them, search from the declared entry points, and
decide.

One rule here is absolute and is checked separately below: a fixture expecting
``affected`` must never be reported ``not_affected``. Every other disagreement
is a bug to fix; that one would be a false clearance, which is the failure this
project exists to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from vexpath_core.enums import ReachStatus, Verdict
from vexpath_core.models.advisory import Advisory
from vexpath_core.models.finding import AdvisoryRef, ComponentRef, Finding, ReachabilityResult
from vexpath_core.reach import (
    ReachabilityContext,
    SourceRoot,
    apply,
    build,
    choose,
    link,
    mentioned_symbols,
    search,
)
from vexpath_core.snapshot import read_snapshot

#: Distribution name to the directory it occupies under a fixture's ``vendor``.
VENDORED_PACKAGES = {
    "requests": "requests",
    "urllib3": "urllib3",
    "jinja2": "jinja2",
    "pyyaml": "yaml",
    "fixturelib": "fixturelib",
}

FIXTURES = (
    "direct-call",
    "method-chain",
    "subclass-override",
    "dynamic-dispatch",
    "unused-transitive",
    "module-level",
)


@dataclass(frozen=True, slots=True)
class Outcome:
    """What the pipeline concluded for one expectation."""

    expectation: dict[str, Any]
    finding: Finding
    reach: ReachabilityResult


def _analyse(root: Path, advisories: dict[str, Advisory]) -> list[Outcome]:
    """Run the full pipeline over one fixture repository."""
    spec = yaml.safe_load((root / "expected.yaml").read_text(encoding="utf-8"))

    graphs = [build([SourceRoot(path=root / "src")])]
    analysed: set[str] = set()
    vendor = root / "vendor"
    if vendor.is_dir():
        for package, directory in VENDORED_PACKAGES.items():
            if (vendor / directory).is_dir():
                graphs.append(build([SourceRoot(path=vendor, package=package)], package=package))
                analysed.add(package)

    graph = link(graphs)
    entry_points, info = choose(graph, configured=spec.get("entry_points", ()), root=root)
    result = search(graph, entry_points)
    context = ReachabilityContext(
        graph=graph,
        result=result,
        entry_points=info,
        analysed_packages=frozenset(analysed),
        mentioned=mentioned_symbols(graph),
    )

    outcomes: list[Outcome] = []
    for expectation in spec["expected"]:
        advisory = advisories[expectation["advisory"]]
        purl = expectation["component"]
        name = purl.split("/", 1)[1].split("@")[0]
        version = purl.split("@")[1]
        finding = Finding(
            id="benchmark",
            advisory=AdvisoryRef(id=advisory.id, severity=advisory.severity),
            component=ComponentRef(
                purl=purl, ecosystem="PyPI", name=name, version=version, direct=True
            ),
            verdict=Verdict.AFFECTED,
        )
        decided = apply(finding, advisory.symbols_for("PyPI", name), context)
        assert decided.reach is not None
        outcomes.append(Outcome(expectation=expectation, finding=decided, reach=decided.reach))
    return outcomes


@pytest.fixture(scope="module")
def advisories(snapshot_dir: Path) -> dict[str, Advisory]:
    _, records = read_snapshot(snapshot_dir)
    return {record.id: record for record in records}


@pytest.fixture(scope="module")
def outcomes(fixture_repos_dir: Path, advisories: dict[str, Advisory]) -> dict[str, list[Outcome]]:
    return {name: _analyse(fixture_repos_dir / name, advisories) for name in FIXTURES}


# --- The rule that must never break ---------------------------------------


def test_nothing_expecting_affected_is_ever_cleared(
    outcomes: dict[str, list[Outcome]],
) -> None:
    """A false clearance is the one failure this project treats as unacceptable.

    Checked on its own, ahead of the per-fixture assertions, so that a
    regression here is unmistakable in the test output rather than one of
    several failures.
    """
    violations = [
        f"{name}: {outcome.finding.advisory.id} expected "
        f"{outcome.expectation['verdict']} but was cleared as not_affected"
        for name, results in outcomes.items()
        for outcome in results
        if outcome.expectation["verdict"] == "affected"
        and outcome.finding.verdict is Verdict.NOT_AFFECTED
    ]
    assert not violations, violations


# --- Per-fixture agreement -------------------------------------------------


@pytest.mark.parametrize("name", FIXTURES)
def test_the_fixture_gets_the_verdict_it_declares(
    name: str, outcomes: dict[str, list[Outcome]]
) -> None:
    for outcome in outcomes[name]:
        expectation = outcome.expectation
        assert outcome.finding.verdict.value == expectation["verdict"], (
            f"{name}/{outcome.finding.advisory.id}: {outcome.reach.explanation}"
        )
        assert outcome.reach.status.value == expectation["reach_status"], (
            f"{name}/{outcome.finding.advisory.id}: {outcome.reach.explanation}"
        )
        assert outcome.reach.confidence.value == expectation["confidence"]


@pytest.mark.parametrize("name", FIXTURES)
def test_the_declared_symbols_are_the_ones_matched(
    name: str, outcomes: dict[str, list[Outcome]]
) -> None:
    for outcome in outcomes[name]:
        expectation = outcome.expectation
        for symbol in expectation.get("must_include_symbols", []):
            assert symbol in outcome.reach.matched_symbols, (
                f"{name}: expected to reach {symbol}, reached {outcome.reach.matched_symbols}"
            )
        for symbol in expectation.get("must_search_symbols", []):
            assert symbol in outcome.reach.searched_symbols, (
                f"{name}: expected to have searched for {symbol}"
            )


@pytest.mark.parametrize("name", FIXTURES)
def test_a_reachable_verdict_comes_with_a_path(
    name: str, outcomes: dict[str, list[Outcome]]
) -> None:
    """Evidence is not optional. A verdict without it is an assertion."""
    for outcome in outcomes[name]:
        if not outcome.reach.status.is_reachable:
            continue
        path = outcome.reach.shortest_path
        assert path, f"{name}: reachable with no path"
        assert path[-1].symbol in outcome.reach.matched_symbols
        # The path starts at something the search was told to start from.
        assert outcome.reach.entry_points is not None
        assert path[0].symbol.startswith("app")


@pytest.mark.parametrize("name", FIXTURES)
def test_an_unreachable_verdict_says_what_it_searched_for(
    name: str, outcomes: dict[str, list[Outcome]]
) -> None:
    for outcome in outcomes[name]:
        if outcome.reach.status is not ReachStatus.UNREACHABLE:
            continue
        assert outcome.reach.searched_symbols
        assert outcome.reach.explanation
        assert outcome.finding.justification is not None


def test_a_guessed_path_is_never_reported_as_certain(
    outcomes: dict[str, list[Outcome]],
) -> None:
    dynamic = next(
        outcome
        for outcome in outcomes["dynamic-dispatch"]
        if outcome.finding.advisory.id == "CVE-2024-FIXTURE-DYNAMIC"
    )
    assert dynamic.reach.status is ReachStatus.REACHABLE_POSSIBLE
    assert dynamic.reach.via_dynamic_edges
    # And it still blocks: possible is reported as affected, not cleared.
    assert dynamic.finding.verdict is Verdict.AFFECTED


def test_the_unused_dependency_is_the_only_one_cleared(
    outcomes: dict[str, list[Outcome]],
) -> None:
    """This is the finding the product exists to remove from the list."""
    cleared = {
        name
        for name, results in outcomes.items()
        for outcome in results
        if outcome.finding.verdict is Verdict.NOT_AFFECTED
    }
    assert cleared == {"unused-transitive"}


def test_the_whole_dependency_chain_is_traversed(
    outcomes: dict[str, list[Outcome]],
) -> None:
    """The path runs through the dependency's internals, not just its surface.

    Reaching ``requests.get`` is easy. Reaching ``Session.send`` four calls
    deeper is the thing that makes a verdict worth anything.
    """
    outcome = outcomes["direct-call"][0]
    symbols = [step.symbol for step in outcome.reach.shortest_path]
    assert symbols[0].startswith("app.")
    assert any(symbol.startswith("requests.api") for symbol in symbols)
    assert symbols[-1] == "requests.sessions.Session.send"
    assert len(symbols) >= 4


def test_graph_statistics_travel_with_every_verdict(
    outcomes: dict[str, list[Outcome]],
) -> None:
    # A reader weighing an unreachable result needs to know how much the
    # analysis could not resolve.
    for results in outcomes.values():
        for outcome in results:
            stats = outcome.reach.graph_stats
            assert stats is not None
            assert stats.first_party_nodes > 0
            assert 0.0 <= stats.unresolved_call_ratio <= 1.0
