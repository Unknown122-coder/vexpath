"""End-to-end scans against the fixture repositories.

These exercise the whole M1 pipeline: find a lockfile, build an inventory,
match it against the frozen corpus, and produce results. They run entirely
offline, which is the property that makes a scan reproducible.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sscp_core import RESULTS_SCHEMA
from sscp_core.advisory import SnapshotSource
from sscp_core.enums import ComponentScope, ScanMode, Severity, Verdict
from sscp_core.models.results import ScanResults
from sscp_core.protocols import FixedClock
from sscp_core.scan import ScanOptions, scan, scanned_lockfile

CLOCK = FixedClock(datetime(2026, 11, 9, 12, 0, tzinfo=UTC))


@pytest.fixture
def source(snapshot_dir: Path) -> SnapshotSource:
    return SnapshotSource(snapshot_dir)


def test_a_scan_reports_the_expected_finding(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = scan(fixture_repos_dir / "direct-call", source, clock=CLOCK)

    assert results.schema_version == RESULTS_SCHEMA
    assert results.mode is ScanMode.CLI
    assert len(results.findings) == 1
    finding = results.findings[0]
    assert finding.advisory.id == "CVE-2024-35195"
    assert finding.component.name == "requests"
    assert finding.fixed_in == "2.32.0"


def test_a_scan_against_a_snapshot_is_reproducible(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = scan(fixture_repos_dir / "direct-call", source, clock=CLOCK)
    assert results.is_reproducible
    assert results.advisory_snapshot_id == "test-snapshot-0001"


def test_two_scans_of_an_unchanged_project_agree(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    first = scan(fixture_repos_dir / "unused-transitive", source, clock=CLOCK)
    second = scan(fixture_repos_dir / "unused-transitive", source, clock=CLOCK)

    assert first.sbom is not None
    assert second.sbom is not None
    assert first.sbom.sha256 == second.sbom.sha256
    # Finding identifiers are fresh per scan, so compare what they say.
    assert [(f.advisory.id, f.component.purl, f.verdict) for f in first.findings] == [
        (f.advisory.id, f.component.purl, f.verdict) for f in second.findings
    ]


def test_nothing_is_cleared_without_reachability(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    """The unused dependency is genuinely unreachable, and this build cannot
    prove it, so it must be reported rather than cleared."""
    results = scan(fixture_repos_dir / "unused-transitive", source, clock=CLOCK)

    urllib3 = next(f for f in results.findings if f.component.name == "urllib3")
    assert urllib3.verdict is Verdict.AFFECTED
    assert urllib3.reach is None
    assert results.counts_by_verdict()[Verdict.NOT_AFFECTED] == 0


def test_a_module_level_advisory_is_matched(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = scan(fixture_repos_dir / "module-level", source, clock=CLOCK)
    assert [f.advisory.id for f in results.findings] == ["CVE-2020-14343"]
    assert results.findings[0].advisory.severity is Severity.CRITICAL


def test_a_synthetic_dependency_still_matches(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    # The dynamic-dispatch fixture vendors a synthetic package; matching must
    # work on the lockfile entry regardless of where the code lives.
    results = scan(fixture_repos_dir / "dynamic-dispatch", source, clock=CLOCK)
    assert [f.advisory.id for f in results.findings] == ["CVE-2024-FIXTURE-DYNAMIC"]


def test_an_explicit_sbom_can_be_analysed_instead_of_a_lockfile(
    sboms_dir: Path, source: SnapshotSource, tmp_path: Path
) -> None:
    options = ScanOptions(sbom_path=sboms_dir / "direct-call.cdx-1.6.json")
    results = scan(tmp_path, source, options=options, clock=CLOCK)
    found = {finding.component.name for finding in results.findings}
    assert found == {"requests", "urllib3"}


def test_development_dependencies_can_be_excluded(
    sboms_dir: Path, source: SnapshotSource, tmp_path: Path
) -> None:
    # The fixture document marks pytest as optional scope, so restricting to
    # runtime narrows the inventory that gets matched.
    options = ScanOptions(
        sbom_path=sboms_dir / "direct-call.cdx-1.6.json",
        include_scopes=frozenset({ComponentScope.RUNTIME}),
    )
    results = scan(tmp_path, source, options=options, clock=CLOCK)
    assert results.sbom is not None
    assert {finding.component.name for finding in results.findings} == {"requests", "urllib3"}


def test_unsupported_ecosystems_are_declared(
    sboms_dir: Path, source: SnapshotSource, tmp_path: Path
) -> None:
    options = ScanOptions(sbom_path=sboms_dir / "mixed-ecosystems.cdx-1.6.json")
    results = scan(tmp_path, source, options=options, clock=CLOCK)
    assert set(results.unsupported_reachability_ecosystems) >= {"npm", "Go"}


def test_results_round_trip_through_json(fixture_repos_dir: Path, source: SnapshotSource) -> None:
    # The results document is the contract with the Action and the platform, so
    # it has to survive serialisation exactly.
    results = scan(fixture_repos_dir / "direct-call", source, clock=CLOCK)
    payload = results.model_dump_json(by_alias=True)
    restored = ScanResults.model_validate_json(payload)
    assert restored == results
    assert '"schema":' in payload


def test_the_summary_line_counts_what_it_says(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = scan(fixture_repos_dir / "unused-transitive", source, clock=CLOCK)
    summary = results.summary_line()
    assert summary.startswith("2 findings")
    assert "0 reachable" in summary


def test_the_lockfile_a_report_anchors_to_is_identified(fixture_repos_dir: Path) -> None:
    repo = fixture_repos_dir / "direct-call"
    assert scanned_lockfile(repo) == "requirements.txt"


def test_a_project_with_no_lockfile_fails_rather_than_reporting_clean(
    tmp_path: Path, source: SnapshotSource
) -> None:
    """An empty inventory would look like a clean project, which is a lie."""
    from sscp_core.sbom import LockfileError

    with pytest.raises(LockfileError):
        scan(tmp_path, source, clock=CLOCK)


@pytest.mark.parametrize(
    "fixture",
    ["direct-call", "method-chain", "subclass-override", "module-level", "dynamic-dispatch"],
)
def test_every_affected_fixture_produces_its_finding(
    fixture: str, fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    """Each fixture expecting an affected verdict must actually match.

    The reachability benchmark in M2 builds on these; if matching misses here,
    that benchmark would fail for the wrong reason.
    """
    import yaml

    expected = yaml.safe_load(
        (fixture_repos_dir / fixture / "expected.yaml").read_text(encoding="utf-8")
    )
    wanted = {entry["advisory"] for entry in expected["expected"] if entry["verdict"] == "affected"}
    results = scan(fixture_repos_dir / fixture, source, clock=CLOCK)
    assert wanted <= {finding.advisory.id for finding in results.findings}
