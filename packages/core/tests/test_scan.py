"""End-to-end scans against the fixture repositories.

These exercise inventory and matching: find a lockfile, build an inventory,
match it against the frozen corpus, and produce results. They run entirely
offline, which is the property that makes a scan reproducible.

Reachability is off in most of them. Left on, each would read whatever
dependencies happen to be installed in the environment running the suite, and
two developers would see different verdicts for the same fixture. The
reachability stage is covered in ``test_reach_environment.py``, against an
environment built on purpose.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vexpath_core import RESULTS_SCHEMA
from vexpath_core.advisory import SnapshotSource
from vexpath_core.enums import ComponentScope, ScanMode, Severity, Verdict
from vexpath_core.models.results import ScanResults
from vexpath_core.protocols import FixedClock
from vexpath_core.scan import ScanOptions, scan, scanned_lockfile

CLOCK = FixedClock(datetime(2026, 11, 9, 12, 0, tzinfo=UTC))


@pytest.fixture
def source(snapshot_dir: Path) -> SnapshotSource:
    return SnapshotSource(snapshot_dir)


def matching_only(root: Path, source: SnapshotSource) -> ScanResults:
    """Scan with reachability off, so the result depends only on the fixture."""
    return scan(root, source, options=ScanOptions(reachability=False), clock=CLOCK)


def test_a_scan_reports_the_expected_finding(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = matching_only(fixture_repos_dir / "direct-call", source)

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
    results = matching_only(fixture_repos_dir / "direct-call", source)
    assert results.is_reproducible
    assert results.advisory_snapshot_id == "test-snapshot-0001"


def test_two_scans_of_an_unchanged_project_agree(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    first = matching_only(fixture_repos_dir / "unused-transitive", source)
    second = matching_only(fixture_repos_dir / "unused-transitive", source)

    assert first.sbom is not None
    assert second.sbom is not None
    assert first.sbom.sha256 == second.sbom.sha256
    # Finding identifiers are fresh per scan, so compare what they say.
    assert [(f.advisory.id, f.component.purl, f.verdict) for f in first.findings] == [
        (f.advisory.id, f.component.purl, f.verdict) for f in second.findings
    ]


def test_nothing_is_cleared_when_reachability_does_not_run(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    """The unused dependency is genuinely unreachable, and this scan did not
    prove it, so it must be reported rather than cleared."""
    results = matching_only(fixture_repos_dir / "unused-transitive", source)

    urllib3 = next(f for f in results.findings if f.component.name == "urllib3")
    assert urllib3.verdict is Verdict.AFFECTED
    assert urllib3.reach is None
    assert results.counts_by_verdict()[Verdict.NOT_AFFECTED] == 0
    # Said out loud, so a short report is never mistaken for a clean one.
    assert any("not run" in note for note in results.analysis_notes)


def test_nothing_is_cleared_when_a_dependency_cannot_be_analysed(
    fixture_repos_dir: Path, source: SnapshotSource, tmp_path: Path
) -> None:
    """Absent evidence is not evidence of absence.

    Reachability ran and found no path, but only because the dependency's
    source was nowhere to be read. That must not clear anything.
    """
    empty = tmp_path / "env"
    (empty / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    options = ScanOptions(environment=empty, use_cache=False)
    results = scan(fixture_repos_dir / "unused-transitive", source, options=options, clock=CLOCK)

    assert results.findings
    assert results.counts_by_verdict()[Verdict.NOT_AFFECTED] == 0
    for finding in results.findings:
        assert finding.verdict is Verdict.UNDER_INVESTIGATION
        assert finding.reach is not None
        assert not finding.reach.status.may_suppress
    assert any("could not be analysed" in note for note in results.analysis_notes)
    assert any("not installed" in note for note in results.analysis_notes)


def test_a_module_level_advisory_is_matched(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = matching_only(fixture_repos_dir / "module-level", source)
    assert [f.advisory.id for f in results.findings] == ["CVE-2020-14343"]
    assert results.findings[0].advisory.severity is Severity.CRITICAL


def test_a_synthetic_dependency_still_matches(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    # The dynamic-dispatch fixture vendors a synthetic package; matching must
    # work on the lockfile entry regardless of where the code lives.
    results = matching_only(fixture_repos_dir / "dynamic-dispatch", source)
    assert [f.advisory.id for f in results.findings] == ["CVE-2024-FIXTURE-DYNAMIC"]


def test_an_explicit_sbom_can_be_analysed_instead_of_a_lockfile(
    sboms_dir: Path, source: SnapshotSource, tmp_path: Path
) -> None:
    options = ScanOptions(sbom_path=sboms_dir / "direct-call.cdx-1.6.json", reachability=False)
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
        reachability=False,
    )
    results = scan(tmp_path, source, options=options, clock=CLOCK)
    assert results.sbom is not None
    assert {finding.component.name for finding in results.findings} == {"requests", "urllib3"}


def test_unsupported_ecosystems_are_declared(
    sboms_dir: Path, source: SnapshotSource, tmp_path: Path
) -> None:
    options = ScanOptions(sbom_path=sboms_dir / "mixed-ecosystems.cdx-1.6.json", reachability=False)
    results = scan(tmp_path, source, options=options, clock=CLOCK)
    assert set(results.unsupported_reachability_ecosystems) >= {"npm", "Go"}


def test_results_round_trip_through_json(fixture_repos_dir: Path, source: SnapshotSource) -> None:
    # The results document is the contract with the Action and the platform, so
    # it has to survive serialisation exactly.
    results = matching_only(fixture_repos_dir / "direct-call", source)
    payload = results.model_dump_json(by_alias=True)
    restored = ScanResults.model_validate_json(payload)
    assert restored == results
    assert '"schema":' in payload


def test_the_summary_line_counts_what_it_says(
    fixture_repos_dir: Path, source: SnapshotSource
) -> None:
    results = matching_only(fixture_repos_dir / "unused-transitive", source)
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
    from vexpath_core.sbom import LockfileError

    with pytest.raises(LockfileError):
        matching_only(tmp_path, source)


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
    results = matching_only(fixture_repos_dir / fixture, source)
    assert wanted <= {finding.advisory.id for finding in results.findings}


# --- Saying which problem it is -------------------------------------------


def test_the_reason_a_package_was_not_analysed_is_grouped_and_named() -> None:
    """Two causes that need opposite responses must not read the same.

    Scanning a real project reported "16 package(s) had no source to analyse
    (argon2-cffi, fastapi, ...)" while every one of them was installed and
    readable: the environment held newer versions than the lockfile. The
    reader's next move for that is to reconcile the two, and for a genuinely
    missing package it is to install it -- so a message that cannot tell them
    apart sends half its readers the wrong way.
    """
    from vexpath_core.scan import _unavailable_notes

    notes = _unavailable_notes(
        {
            "fastapi": (
                "the environment has 0.162.0 but the inventory says 0.115.6, so its "
                "graph would describe code this project does not ship"
            ),
            "pillow": (
                "the environment has 13.0.0 but the inventory says 10.4.0, so its "
                "graph would describe code this project does not ship"
            ),
            "requests": "not installed in the environment being scanned",
        }
    )

    assert len(notes) == 2, notes
    # The mismatches group together even though each reason names different
    # versions, which is the case the grouping exists for.
    mismatch = next(note for note in notes if "different version" in note)
    assert "2 package(s)" in mismatch
    assert "fastapi" in mismatch
    assert "pillow" in mismatch

    missing = next(note for note in notes if "not installed" in note)
    assert "requests" in missing
    assert "fastapi" not in missing


def test_a_long_list_of_packages_is_summarised_rather_than_printed() -> None:
    from vexpath_core.scan import NAMED_IN_A_NOTE, _unavailable_notes

    unavailable = {
        f"package{index}": "not installed in the environment being scanned"
        for index in range(NAMED_IN_A_NOTE + 3)
    }

    note = _unavailable_notes(unavailable)[0]

    assert "and 3 more" in note
    # The first few by name, the rest counted. Asserted on the names rather
    # than on comma arithmetic, which also counts the prose.
    assert f"package{NAMED_IN_A_NOTE - 1}" in note
    assert f"package{NAMED_IN_A_NOTE}" not in note
