"""Explaining one advisory against one project.

The invariant these exist to protect is that triage and scan never disagree.
Everything else here is about evidence: that the report names what it searched
for, says where each symbol came from, and distinguishes an entry point that
reaches the vulnerable code from one that does not.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vexpath_core import report
from vexpath_core.advisory import SnapshotSource
from vexpath_core.enums import (
    Confidence,
    EntryPointSource,
    ReachReason,
    ReachStatus,
    SymbolSource,
    Verdict,
)
from vexpath_core.protocols import FixedClock
from vexpath_core.scan import ScanOptions, scan
from vexpath_core.triage import TriageError, triage

CLOCK = FixedClock(datetime(2026, 11, 9, 12, 0, tzinfo=UTC))

#: Advisory identifiers the frozen corpus carries for the fixtures.
REQUESTS_ADVISORY = "CVE-2024-35195"
URLLIB3_ADVISORY = "CVE-2023-45803"
URLLIB3_ALIAS = "GHSA-g4mx-q9vg-27p4"


def _install(site_packages: Path, distribution: str, version: str, name: str, vendor: Path) -> None:
    shutil.copytree(vendor / name, site_packages / name)
    info = site_packages / f"{distribution}-{version}.dist-info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "METADATA").write_text(f"Name: {distribution}\nVersion: {version}\n", encoding="utf-8")
    (info / "top_level.txt").write_text(f"{name}\n", encoding="utf-8")


@pytest.fixture
def source(snapshot_dir: Path) -> SnapshotSource:
    return SnapshotSource(snapshot_dir)


@pytest.fixture
def reachable_env(tmp_path: Path, fixture_repos_dir: Path) -> Path:
    """An environment for the direct-call fixture, whose finding is reachable."""
    site_packages = tmp_path / "direct" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    _install(
        site_packages,
        "requests",
        "2.31.0",
        "requests",
        fixture_repos_dir / "direct-call" / "vendor",
    )
    return tmp_path / "direct"


@pytest.fixture
def unreachable_env(tmp_path: Path, fixture_repos_dir: Path) -> Path:
    """An environment for the unused-transitive fixture, whose findings clear."""
    site_packages = tmp_path / "unused" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    vendor = fixture_repos_dir / "unused-transitive" / "vendor"
    _install(site_packages, "requests", "2.31.0", "requests", vendor)
    _install(site_packages, "urllib3", "1.26.17", "urllib3", vendor)
    return tmp_path / "unused"


def _triage(
    project: Path, advisory: str, source: SnapshotSource, environment: Path, **extra: object
):
    options = ScanOptions(environment=environment, use_cache=False)
    return triage(project, advisory, source, options=options, clock=CLOCK, **extra)  # type: ignore[arg-type]


# --- The answer -----------------------------------------------------------


def test_a_reachable_advisory_is_explained_as_reachable(
    fixture_repos_dir: Path, source: SnapshotSource, reachable_env: Path
) -> None:
    result = _triage(fixture_repos_dir / "direct-call", REQUESTS_ADVISORY, source, reachable_env)

    assert result.advisory_id == REQUESTS_ADVISORY
    assert result.component.name == "requests"
    assert result.version_affected
    assert result.verdict is Verdict.AFFECTED
    assert result.reach is not None
    assert result.reach.status is ReachStatus.REACHABLE_CONFIRMED
    assert result.is_reproducible


def test_an_unreachable_advisory_is_explained_as_cleared(
    fixture_repos_dir: Path, source: SnapshotSource, unreachable_env: Path
) -> None:
    result = _triage(
        fixture_repos_dir / "unused-transitive", URLLIB3_ADVISORY, source, unreachable_env
    )

    assert result.verdict is Verdict.NOT_AFFECTED
    assert result.reach is not None
    assert result.reach.status is ReachStatus.UNREACHABLE
    assert result.reaching_entry_points == ()
    # The symbol is there; it is simply never called.
    assert all(probe.defined and not probe.missing for probe in result.symbols)
    assert all(probe.status == "unreached" for probe in result.symbols)


def test_triage_and_scan_never_disagree(
    fixture_repos_dir: Path, source: SnapshotSource, unreachable_env: Path
) -> None:
    """The invariant. A triage tool that contradicts its own scan is useless."""
    project = fixture_repos_dir / "unused-transitive"
    options = ScanOptions(environment=unreachable_env, use_cache=False)
    results = scan(project, source, options=options, clock=CLOCK)

    for finding in results.findings:
        explained = triage(project, finding.advisory.id, source, options=options, clock=CLOCK)
        assert explained.verdict is finding.verdict
        assert finding.reach is not None
        assert explained.reach is not None
        assert explained.reach.status is finding.reach.status
        assert explained.reach.confidence is finding.reach.confidence


def test_an_advisory_is_found_by_any_of_its_identifiers(
    fixture_repos_dir: Path, source: SnapshotSource, unreachable_env: Path
) -> None:
    # Someone pasting a GHSA identifier from a dependabot alert must not be
    # told the advisory does not exist.
    by_alias = _triage(
        fixture_repos_dir / "unused-transitive", URLLIB3_ALIAS, source, unreachable_env
    )
    by_cve = _triage(
        fixture_repos_dir / "unused-transitive", URLLIB3_ADVISORY, source, unreachable_env
    )
    assert by_alias.advisory_id == by_cve.advisory_id
    assert by_alias.verdict is by_cve.verdict


def test_a_lowercase_identifier_is_accepted(
    fixture_repos_dir: Path, source: SnapshotSource, unreachable_env: Path
) -> None:
    result = _triage(
        fixture_repos_dir / "unused-transitive",
        URLLIB3_ADVISORY.lower(),
        source,
        unreachable_env,
    )
    assert result.advisory_id == URLLIB3_ADVISORY


def test_an_unknown_advisory_says_so_rather_than_reporting_nothing(
    fixture_repos_dir: Path, source: SnapshotSource, unreachable_env: Path
) -> None:
    with pytest.raises(TriageError, match="no advisory matching"):
        _triage(fixture_repos_dir / "unused-transitive", "CVE-9999-00001", source, unreachable_env)


def test_an_advisory_for_another_package_is_refused(
    fixture_repos_dir: Path, source: SnapshotSource, unreachable_env: Path
) -> None:
    """The unused-transitive fixture has no jinja2, so its advisory cannot apply."""
    with pytest.raises(TriageError, match="inventory"):
        _triage(fixture_repos_dir / "unused-transitive", "CVE-2024-22195", source, unreachable_env)


# --- The evidence ---------------------------------------------------------


def test_each_entry_point_is_answered_separately(
    fixture_repos_dir: Path, source: SnapshotSource, reachable_env: Path
) -> None:
    """Reachable from a request handler is a different problem from reachable
    from a one-off script, so the report does not merge them."""
    result = _triage(fixture_repos_dir / "direct-call", REQUESTS_ADVISORY, source, reachable_env)

    assert len(result.entry_points) > 1
    reaching = result.reaching_entry_points
    assert reaching, "the direct-call fixture calls the vulnerable code"
    assert len(reaching) < len(result.entry_points), "and the package root does not"
    # Reaching entry points come first, because that is what a reader came for.
    assert result.entry_points[0].reaches

    best = reaching[0]
    assert best.path[0].symbol == best.entry_point
    assert best.path[-1].symbol == best.symbol


def test_a_path_names_the_file_and_line_of_every_hop(
    fixture_repos_dir: Path, source: SnapshotSource, reachable_env: Path
) -> None:
    result = _triage(fixture_repos_dir / "direct-call", REQUESTS_ADVISORY, source, reachable_env)
    path = result.reaching_entry_points[0].path
    assert len(path) >= 4
    for step in path:
        assert step.file, f"{step.symbol} has no file"
        assert step.line is not None


def test_entry_point_provenance_is_reported(
    fixture_repos_dir: Path, source: SnapshotSource, reachable_env: Path
) -> None:
    inferred = _triage(fixture_repos_dir / "direct-call", REQUESTS_ADVISORY, source, reachable_env)
    assert inferred.entry_point_source is EntryPointSource.FALLBACK_PUBLIC

    told = triage(
        fixture_repos_dir / "direct-call",
        REQUESTS_ADVISORY,
        source,
        options=ScanOptions(
            environment=reachable_env, use_cache=False, entry_points=("app.main:main",)
        ),
        clock=CLOCK,
    )
    assert told.entry_point_source is EntryPointSource.CONFIG
    # Being told how the application starts raises confidence in a reachable
    # verdict, because the path provably begins somewhere that runs.
    assert told.reach is not None
    assert inferred.reach is not None
    assert told.reach.confidence.rank >= inferred.reach.confidence.rank


def test_a_symbol_supplied_by_hand_is_recorded_as_unverified(
    fixture_repos_dir: Path, source: SnapshotSource, unreachable_env: Path
) -> None:
    """An operator's assertion is usable evidence, but it is not a fix commit."""
    result = _triage(
        fixture_repos_dir / "unused-transitive",
        URLLIB3_ADVISORY,
        source,
        unreachable_env,
        extra_symbols=("urllib3.connectionpool.HTTPConnectionPool.urlopen",),
    )

    manual = [probe for probe in result.symbols if probe.source is SymbolSource.MANUAL]
    assert len(manual) == 1
    assert manual[0].confidence is Confidence.LOW
    assert any("command line" in note for note in result.notes)


def test_a_hand_supplied_symbol_can_turn_a_verdict(
    fixture_repos_dir: Path, source: SnapshotSource, unreachable_env: Path
) -> None:
    # The fixture never calls urllib3, so naming a symbol it does call proves
    # the search is really driven by the symbols given.
    result = _triage(
        fixture_repos_dir / "unused-transitive",
        URLLIB3_ADVISORY,
        source,
        unreachable_env,
        extra_symbols=("app.compute.mean",),
    )
    assert result.verdict is Verdict.AFFECTED
    assert result.reach is not None
    # Low, because nothing checked that this symbol is the vulnerable one.
    assert result.reach.confidence is Confidence.LOW


def test_a_dependency_with_no_source_is_not_cleared(
    fixture_repos_dir: Path, source: SnapshotSource, tmp_path: Path
) -> None:
    """Absence of evidence, reported as such."""
    empty = tmp_path / "empty"
    (empty / "Lib" / "site-packages").mkdir(parents=True)
    result = _triage(fixture_repos_dir / "unused-transitive", URLLIB3_ADVISORY, source, empty)

    assert result.verdict is Verdict.UNDER_INVESTIGATION
    assert result.reach is not None
    assert result.reach.reason is ReachReason.PACKAGE_NOT_ANALYSED
    assert not result.reach.status.may_suppress
    assert any("could not be analysed" in note for note in result.notes)


def test_the_graph_the_answer_rests_on_is_reported(
    fixture_repos_dir: Path, source: SnapshotSource, reachable_env: Path
) -> None:
    result = _triage(fixture_repos_dir / "direct-call", REQUESTS_ADVISORY, source, reachable_env)
    assert result.graph is not None
    assert result.graph.first_party_nodes > 0
    assert result.graph.linked_packages >= 1
    assert 0.0 <= result.graph.unresolved_call_ratio <= 1.0


def test_the_call_count_is_calls_and_not_path_steps(
    fixture_repos_dir: Path, source: SnapshotSource, reachable_env: Path
) -> None:
    """A reader who counts the printed hops must get the printed number.

    A path of five symbols is four calls. Claiming five is the kind of small
    wrongness that makes someone distrust the whole report.
    """
    result = _triage(fixture_repos_dir / "direct-call", REQUESTS_ADVISORY, source, reachable_env)
    assert result.reach is not None
    hops = len(result.reach.shortest_path) - 1
    assert f"through {hops} resolved call(s)" in result.reach.explanation


# --- The rendering --------------------------------------------------------


def test_the_rendered_report_leads_with_the_answer(
    fixture_repos_dir: Path, source: SnapshotSource, unreachable_env: Path
) -> None:
    result = _triage(
        fixture_repos_dir / "unused-transitive", URLLIB3_ADVISORY, source, unreachable_env
    )
    text = report.render_triage(result)

    assert text.startswith(URLLIB3_ADVISORY)
    assert "not_affected" in text
    assert "unreachable" in text
    assert "Vulnerable symbols searched for" in text
    assert "Graph the answer rests on" in text
    assert text.endswith("\n")


def test_the_rendered_report_shows_every_reaching_path(
    fixture_repos_dir: Path, source: SnapshotSource, reachable_env: Path
) -> None:
    result = _triage(fixture_repos_dir / "direct-call", REQUESTS_ADVISORY, source, reachable_env)
    text = report.render_triage(result)

    for entry in result.reaching_entry_points:
        assert entry.entry_point in text
    assert "requests.sessions.Session.send" in text
    assert "Pass --entry-point" in text


def test_the_rendered_report_is_ascii(
    fixture_repos_dir: Path, source: SnapshotSource, reachable_env: Path
) -> None:
    # A middle dot or an arrow renders as a question mark in the Windows
    # console, which is where this output is read.
    text = report.render_triage(
        _triage(fixture_repos_dir / "direct-call", REQUESTS_ADVISORY, source, reachable_env)
    )
    assert text.isascii()


def test_the_corpus_a_report_used_is_named_in_it(
    fixture_repos_dir: Path, source: SnapshotSource, reachable_env: Path
) -> None:
    """Without the corpus identifier the report cannot be reproduced later."""
    result = _triage(fixture_repos_dir / "direct-call", REQUESTS_ADVISORY, source, reachable_env)
    assert result.is_reproducible
    assert f"snapshot {result.snapshot_id}" in report.render_triage(result)
