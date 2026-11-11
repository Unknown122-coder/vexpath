"""Matching components against advisories.

This stage decides what a user is shown at all, so the tests concentrate on the
three ways it could be wrong in a damaging direction: reporting a withdrawn
advisory, clearing something it could not actually check, and missing a match
because of a name or version detail.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vexpath_core.advisory.source import SnapshotSource
from vexpath_core.enums import (
    ComponentScope,
    SbomFormat,
    SbomGenerator,
    Severity,
    SymbolsStatus,
    Verdict,
)
from vexpath_core.models.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    RangeEvent,
    RangeType,
)
from vexpath_core.models.sbom import Component, Sbom
from vexpath_core.purl import build_purl
from vexpath_core.vulnmatch import match, summarise_by_severity

NOW = datetime(2026, 11, 9, tzinfo=UTC)


def _component(
    name: str,
    version: str,
    *,
    ecosystem: str = "PyPI",
    direct: bool = True,
    scope: ComponentScope = ComponentScope.RUNTIME,
) -> Component:
    purl = build_purl(ecosystem, name, version)
    return Component(
        bom_ref=purl,
        purl=purl,
        ecosystem=ecosystem,
        name=name,
        version=version,
        direct=direct,
        scope=scope,
    )


def _sbom(*components: Component) -> Sbom:
    return Sbom(
        format=SbomFormat.CYCLONEDX_1_6_JSON,
        spec_version="1.6",
        document_sha256="0" * 64,
        generated_by=SbomGenerator.VEXPATH,
        created_at=NOW,
        components=components,
    )


def _advisory(
    advisory_id: str = "CVE-2024-0001",
    *,
    name: str = "requests",
    ecosystem: str = "PyPI",
    introduced: str = "0",
    fixed: str | None = "2.32.0",
    severity: Severity = Severity.HIGH,
    withdrawn: bool = False,
    versions: tuple[str, ...] = (),
    ranges: tuple[AffectedRange, ...] | None = None,
) -> Advisory:
    if ranges is None:
        events = [RangeEvent(introduced=introduced)]
        if fixed is not None:
            events.append(RangeEvent(fixed=fixed))
        ranges = (AffectedRange(type=RangeType.ECOSYSTEM, events=tuple(events)),)
    return Advisory(
        id=advisory_id,
        summary=f"{advisory_id} summary",
        severity=severity,
        withdrawn_at=NOW if withdrawn else None,
        affected=(
            AffectedPackage(
                ecosystem=ecosystem,
                name=name,
                purl_base=build_purl(ecosystem, name),
                ranges=ranges,
                versions=versions,
            ),
        ),
        symbols_status=SymbolsStatus.PENDING,
    )


def _source(*advisories: Advisory) -> SnapshotSource:
    return SnapshotSource.from_advisories(advisories, snapshot_id="test")


# --- The basic path --------------------------------------------------------


def test_an_affected_version_produces_a_finding() -> None:
    report = match(_sbom(_component("requests", "2.31.0")), _source(_advisory()))
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.verdict is Verdict.AFFECTED
    assert finding.fixed_in == "2.32.0"
    assert finding.advisory.severity is Severity.HIGH
    assert report.advisory_snapshot_id == "test"


def test_a_fixed_version_produces_nothing() -> None:
    report = match(_sbom(_component("requests", "2.32.0")), _source(_advisory()))
    assert report.findings == ()


def test_a_different_package_is_not_matched() -> None:
    report = match(_sbom(_component("flask", "3.0.0")), _source(_advisory()))
    assert report.findings == ()


def test_name_spellings_still_match() -> None:
    # Both sides are normalised at ingest, so a differently spelled name must
    # still join. A miss here is silent and would hide real vulnerabilities.
    report = match(
        _sbom(_component("Flask-SQLAlchemy", "3.0.0")),
        _source(_advisory(name="flask_sqlalchemy", fixed="3.1.0")),
    )
    assert len(report.findings) == 1


# --- Refusals --------------------------------------------------------------


def test_a_withdrawn_advisory_never_produces_a_finding() -> None:
    """A withdrawn advisory is one the database concluded was wrong."""
    report = match(
        _sbom(_component("requests", "2.31.0")),
        _source(_advisory(withdrawn=True)),
    )
    assert report.findings == ()


def test_nothing_is_ever_cleared_at_this_stage() -> None:
    # Only reachability may produce not_affected, and only when it has proven
    # a path does not exist.
    report = match(
        _sbom(_component("requests", "2.31.0"), _component("flask", "3.0.0")),
        _source(_advisory()),
    )
    assert all(finding.verdict is not Verdict.NOT_AFFECTED for finding in report.findings)


def test_an_unorderable_version_is_investigated_not_dismissed() -> None:
    """Where ordering is impossible, the honest answer is 'unknown'."""
    report = match(
        _sbom(_component("jackson-databind", "2.9.10", ecosystem="Maven")),
        _source(_advisory(name="jackson-databind", ecosystem="Maven", fixed="2.10.0")),
    )
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.verdict is Verdict.UNDER_INVESTIGATION
    assert finding.notes
    assert "could not be determined" in finding.notes[0]


def test_an_unorderable_ecosystem_still_matches_an_explicit_version_list() -> None:
    report = match(
        _sbom(_component("jackson-databind", "2.9.10", ecosystem="Maven")),
        _source(
            _advisory(
                name="jackson-databind",
                ecosystem="Maven",
                versions=("2.9.10",),
                ranges=(),
            )
        ),
    )
    assert report.findings[0].verdict is Verdict.AFFECTED


def test_a_component_without_a_version_is_skipped_and_reported() -> None:
    component = Component(
        bom_ref="x", purl="pkg:pypi/mystery", ecosystem="PyPI", name="mystery", version=""
    )
    report = match(_sbom(component), _source(_advisory(name="mystery")))
    assert report.findings == ()
    assert report.skipped
    assert "no version recorded" in report.skipped[0]


# --- Reachability capability ----------------------------------------------


def test_a_non_python_component_is_told_it_was_not_checked() -> None:
    report = match(
        _sbom(_component("lodash", "4.17.20", ecosystem="npm")),
        _source(_advisory(name="lodash", ecosystem="npm", fixed="4.17.21")),
    )
    finding = report.findings[0]
    assert report.unsupported_reachability_ecosystems == ("npm",)
    assert any("not implemented for npm" in note for note in finding.notes)
    assert any("unknown, not cleared" in note for note in finding.notes)


def test_a_python_component_carries_no_capability_caveat() -> None:
    report = match(_sbom(_component("requests", "2.31.0")), _source(_advisory()))
    assert report.findings[0].notes == ()
    assert report.unsupported_reachability_ecosystems == ()


# --- Scope -----------------------------------------------------------------


def test_development_dependencies_are_analysed_by_default() -> None:
    # A compromised build-time dependency is still a compromise; whether to act
    # on it is policy's decision, not matching's.
    report = match(
        _sbom(_component("requests", "2.31.0", scope=ComponentScope.DEV)),
        _source(_advisory()),
    )
    assert len(report.findings) == 1


def test_scopes_can_be_restricted() -> None:
    report = match(
        _sbom(_component("requests", "2.31.0", scope=ComponentScope.DEV)),
        _source(_advisory()),
        include_scopes=frozenset({ComponentScope.RUNTIME}),
    )
    assert report.findings == ()


# --- Ordering and summaries ------------------------------------------------


def test_findings_are_ordered_worst_first() -> None:
    report = match(
        _sbom(
            _component("requests", "2.31.0"),
            _component("urllib3", "1.0.0", direct=False),
            _component("jinja2", "3.1.2"),
        ),
        _source(
            _advisory("CVE-A", name="requests", severity=Severity.MEDIUM),
            _advisory("CVE-B", name="urllib3", severity=Severity.CRITICAL, fixed="2.0.0"),
            _advisory("CVE-C", name="jinja2", severity=Severity.CRITICAL, fixed="3.1.3"),
        ),
    )
    severities = [finding.advisory.severity for finding in report.findings]
    assert severities == [Severity.CRITICAL, Severity.CRITICAL, Severity.MEDIUM]
    # Among equals, a direct dependency comes first: it is actionable without
    # chasing an upgrade chain.
    assert report.findings[0].component.name == "jinja2"
    assert report.findings[0].component.direct


def test_ordering_is_stable_between_runs() -> None:
    sbom = _sbom(_component("requests", "2.31.0"), _component("jinja2", "3.1.2"))
    source = _source(
        _advisory("CVE-A", name="requests"),
        _advisory("CVE-B", name="jinja2", fixed="3.1.3"),
    )
    first = [finding.advisory.id for finding in match(sbom, source).findings]
    second = [finding.advisory.id for finding in match(sbom, source).findings]
    assert first == second


def test_counts_are_reported() -> None:
    report = match(
        _sbom(
            _component("requests", "2.31.0"),
            _component("jackson-databind", "2.9.10", ecosystem="Maven"),
        ),
        _source(
            _advisory(name="requests"),
            _advisory("CVE-M", name="jackson-databind", ecosystem="Maven", fixed="2.10.0"),
        ),
    )
    assert report.affected_count == 1
    assert report.under_investigation_count == 1


def test_severity_summary_includes_empty_buckets() -> None:
    report = match(_sbom(_component("requests", "2.31.0")), _source(_advisory()))
    counts = summarise_by_severity(report.findings)
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.CRITICAL] == 0
    assert set(counts) == set(Severity)


# --- Against the committed fixture snapshot -------------------------------


def test_the_fixture_snapshot_matches_the_fixture_sbom(snapshot_dir: Path, sboms_dir: Path) -> None:
    from vexpath_core.protocols import FixedClock
    from vexpath_core.sbom import load

    sbom = load(sboms_dir / "direct-call.cdx-1.6.json", clock=FixedClock(NOW))
    report = match(sbom, SnapshotSource(snapshot_dir))

    found = {(finding.advisory.id, finding.component.name) for finding in report.findings}
    assert ("CVE-2024-35195", "requests") in found
    assert ("CVE-2023-45803", "urllib3") in found
    # The withdrawn fixture advisory also covers requests 2.31.0, and must not
    # appear.
    assert not any(advisory == "CVE-2024-FIXTURE-WITHDRAWN" for advisory, _ in found)


def test_every_requested_purl_gets_an_answer(snapshot_dir: Path) -> None:
    # A caller must be able to tell "no advisories" from "not looked up".
    source = SnapshotSource(snapshot_dir)
    answers = source.advisories_for(["pkg:pypi/requests@2.31.0", "pkg:pypi/nothing@1.0.0"])
    assert set(answers) == {"pkg:pypi/requests@2.31.0", "pkg:pypi/nothing@1.0.0"}
    assert answers["pkg:pypi/nothing@1.0.0"] == ()


def test_a_malformed_purl_yields_an_empty_answer_not_a_crash(snapshot_dir: Path) -> None:
    source = SnapshotSource(snapshot_dir)
    assert source.advisories_for(["not a purl"])["not a purl"] == ()


def test_a_live_source_declares_itself_unreproducible() -> None:
    from vexpath_core.advisory import OsvApiSource

    with OsvApiSource() as source:
        assert source.snapshot_id is None


@pytest.mark.parametrize("verify", [True, False])
def test_the_snapshot_source_indexes_the_committed_corpus(snapshot_dir: Path, verify: bool) -> None:
    source = SnapshotSource(snapshot_dir, verify=verify)
    assert len(source) >= 8
    assert source.snapshot_id == "test-snapshot-0001"


# --- One vulnerability, one finding ---------------------------------------


class _DuplicatingSource:
    """A source that returns the same advisory twice, as OSV's live API does.

    Not a contrived case. OSV holds every PyPI vulnerability twice -- once
    from the GitHub Advisory Database as GHSA-..., once from PyPA as
    PYSEC-... -- and both records name the same CVE, which is the identifier
    this project chooses to show.
    """

    snapshot_id = None

    def __init__(self, advisory: Advisory) -> None:
        self._advisory = advisory

    def advisories_for(self, purls: object) -> dict[str, tuple[Advisory, ...]]:
        return dict.fromkeys(purls, (self._advisory, self._advisory))  # type: ignore[union-attr]


def test_the_same_advisory_twice_is_one_finding() -> None:
    """Every number this tool printed for a PyPI project used to be doubled.

    A finding is a statement about one vulnerability in one installed
    package. The same statement twice is not more information; it is a wrong
    count, and a wrong count is the one thing a security report cannot
    afford. Enforced in the matcher rather than trusted of the source,
    because the matcher is where "a finding" is defined.
    """
    report = match(_sbom(_component("requests", "2.31.0")), _DuplicatingSource(_advisory()))

    assert len(report.findings) == 1
    assert report.findings[0].advisory.id == "CVE-2024-0001"


def test_distinct_advisories_on_one_component_are_both_kept() -> None:
    # The deduplication is by identifier, not by package: two real
    # vulnerabilities in one dependency are two findings.
    report = match(
        _sbom(_component("requests", "2.31.0")),
        _source(_advisory("CVE-2024-0001"), _advisory("CVE-2024-0002")),
    )

    assert {finding.advisory.id for finding in report.findings} == {
        "CVE-2024-0001",
        "CVE-2024-0002",
    }
