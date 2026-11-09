"""Rendering results.

Rendering is where an honest analysis can still mislead, so these tests check
what the output actually tells a reader: that uncertainty is visible, that a
live scan is not passed off as reproducible, and that caveats are not dropped.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from vexpath_core import RESULTS_SCHEMA
from vexpath_core.enums import (
    Confidence,
    ReachStatus,
    SbomFormat,
    Severity,
    Verdict,
    VexJustification,
)
from vexpath_core.models.finding import (
    AdvisoryRef,
    CallPathStep,
    ComponentRef,
    Finding,
    ReachabilityResult,
)
from vexpath_core.models.results import (
    PolicyResult,
    PolicyViolation,
    ProjectRef,
    SbomRef,
    ScanResults,
)
from vexpath_core.report import render_markdown, render_sarif, render_text

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def _finding(
    advisory_id: str = "CVE-2024-35195",
    *,
    severity: Severity = Severity.HIGH,
    verdict: Verdict = Verdict.AFFECTED,
    name: str = "requests",
    version: str = "2.31.0",
    direct: bool = True,
    fixed_in: str | None = "2.32.0",
    reach: ReachabilityResult | None = None,
    justification: VexJustification | None = None,
    notes: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        id="01",
        advisory=AdvisoryRef(
            id=advisory_id, summary=f"{advisory_id} summary", severity=severity, cvss_v3_score=7.5
        ),
        component=ComponentRef(
            purl=f"pkg:pypi/{name}@{version}",
            ecosystem="PyPI",
            name=name,
            version=version,
            direct=direct,
        ),
        verdict=verdict,
        fixed_in=fixed_in,
        reach=reach,
        justification=justification,
        notes=notes,
    )


def _results(
    *findings: Finding,
    snapshot_id: str | None = "test-snapshot-0001",
    policy: PolicyResult | None = None,
    unsupported: tuple[str, ...] = (),
) -> ScanResults:
    return ScanResults(
        schema=RESULTS_SCHEMA,
        core_version="0.0.1",
        generated_at=NOW,
        project=ProjectRef(slug="acme/api"),
        sbom=SbomRef(
            format=SbomFormat.CYCLONEDX_1_6_JSON, sha256="0" * 64, component_count=len(findings)
        ),
        advisory_snapshot_id=snapshot_id,
        findings=findings,
        policy=policy,
        unsupported_reachability_ecosystems=unsupported,
    )


def _reachable() -> ReachabilityResult:
    return ReachabilityResult(
        status=ReachStatus.REACHABLE_CONFIRMED,
        confidence=Confidence.HIGH,
        matched_symbols=("requests.sessions.Session.send",),
        searched_symbols=("requests.sessions.Session.send",),
        shortest_path=(
            CallPathStep(symbol="app.main.fetch", file="app/main.py", line=12),
            CallPathStep(
                symbol="requests.sessions.Session.send",
                file="requests/sessions.py",
                line=701,
            ),
        ),
        path_count=1,
    )


def _unreachable() -> ReachabilityResult:
    return ReachabilityResult(
        status=ReachStatus.UNREACHABLE,
        confidence=Confidence.HIGH,
        searched_symbols=("urllib3.poolmanager.PoolManager.urlopen",),
        explanation="The package is imported but the vulnerable symbol is never called.",
    )


# --- Terminal output -------------------------------------------------------


def test_an_empty_result_says_so_plainly() -> None:
    text = render_text(_results())
    assert "No advisories match" in text


def test_findings_are_listed_with_the_upgrade() -> None:
    text = render_text(_results(_finding()))
    assert "CVE-2024-35195" in text
    assert "requests 2.31.0 -> 2.32.0" in text
    assert "HIGH" in text


def test_a_transitive_dependency_is_labelled() -> None:
    text = render_text(_results(_finding(direct=False)))
    assert "(transitive)" in text


def test_cleared_findings_are_hidden_by_default_and_counted() -> None:
    """The product exists to show a short list, so that is the default view."""
    cleared = _finding(
        verdict=Verdict.NOT_AFFECTED,
        reach=_unreachable(),
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    )
    text = render_text(_results(cleared))
    assert "were cleared as unreachable" in text
    assert "--show-cleared" in text

    shown = render_text(_results(cleared), show_cleared=True)
    assert "not reachable" in shown


def test_uncertainty_is_visible_in_the_verdict_column() -> None:
    possible = ReachabilityResult(
        status=ReachStatus.REACHABLE_POSSIBLE,
        confidence=Confidence.LOW,
        matched_symbols=("fixturelib.handlers.Handler.process",),
        via_dynamic_edges=True,
    )
    text = render_text(_results(_finding(reach=possible)))
    # A reader must be able to tell a proven path from a possible one.
    assert "possibly reachable" in text


def test_the_call_path_is_shown_as_evidence() -> None:
    text = render_text(_results(_finding(reach=_reachable())))
    assert "Evidence" in text
    assert "app/main.py:12" in text
    assert "<- vulnerable symbol" in text


def test_caveats_are_not_dropped() -> None:
    text = render_text(_results(_finding(notes=("Reachability is not implemented for npm.",))))
    assert "Caveats" in text
    assert "not implemented for npm" in text


def test_a_live_scan_is_not_passed_off_as_reproducible() -> None:
    text = render_text(_results(_finding(), snapshot_id=None))
    assert "not reproducible" in text
    assert "Advisory snapshot" not in text


def test_a_reproducible_scan_names_its_snapshot() -> None:
    text = render_text(_results(_finding()))
    assert "Advisory snapshot test-snapshot-0001" in text


def test_unsupported_ecosystems_are_stated_in_the_header() -> None:
    text = render_text(_results(_finding(), unsupported=("Go", "npm")))
    assert "does not cover Go, npm" in text
    assert "not cleared" in text


def test_a_failing_policy_is_reported_with_its_reasons() -> None:
    policy = PolicyResult(
        name="balanced",
        passed=False,
        violations=(PolicyViolation(message="1 reachable HIGH older than 14 days"),),
    )
    text = render_text(_results(_finding(), policy=policy))
    assert "Policy balanced: FAILED" in text
    assert "older than 14 days" in text


def test_the_terminal_output_is_ascii_only() -> None:
    # The command line has to be readable in a Windows console, which is not
    # UTF-8 by default.
    text = render_text(_results(_finding(reach=_reachable())))
    assert text.isascii()


# --- Markdown --------------------------------------------------------------


def test_markdown_leads_with_the_counts() -> None:
    markdown = render_markdown(_results(_finding(reach=_reachable())))
    assert markdown.startswith("## Supply-chain scan")
    assert "**1 reachable**" in markdown


def test_markdown_says_so_when_nothing_needs_attention() -> None:
    cleared = _finding(
        verdict=Verdict.NOT_AFFECTED,
        reach=_unreachable(),
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    )
    assert "Nothing needs attention" in render_markdown(_results(cleared))


def test_markdown_puts_call_paths_behind_a_disclosure() -> None:
    markdown = render_markdown(_results(_finding(reach=_reachable())))
    assert "<details>" in markdown
    assert "requests.sessions.Session.send" in markdown


# --- SARIF -----------------------------------------------------------------


def test_sarif_anchors_findings_to_the_lockfile() -> None:
    # A dependency finding has no line of source code, and the lockfile is the
    # file a reader would actually edit.
    document = render_sarif(_results(_finding()), lockfile_path="requirements.txt")
    location = document["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"


def test_sarif_severity_drives_the_level() -> None:
    document = render_sarif(
        _results(
            _finding("CVE-A", severity=Severity.CRITICAL),
            _finding("CVE-B", severity=Severity.LOW, name="jinja2"),
        )
    )
    levels = {result["ruleId"]: result["level"] for result in document["runs"][0]["results"]}
    assert levels["CVE-A"] == "error"
    assert levels["CVE-B"] == "warning"


def test_sarif_excludes_cleared_findings() -> None:
    cleared = _finding(
        verdict=Verdict.NOT_AFFECTED,
        reach=_unreachable(),
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    )
    document = render_sarif(_results(cleared, _finding("CVE-B", name="jinja2")))
    assert [result["ruleId"] for result in document["runs"][0]["results"]] == ["CVE-B"]


def test_sarif_fingerprints_are_stable_so_findings_are_tracked() -> None:
    first = render_sarif(_results(_finding()))
    second = render_sarif(_results(_finding()))
    assert (
        first["runs"][0]["results"][0]["partialFingerprints"]
        == second["runs"][0]["results"][0]["partialFingerprints"]
    )


def test_sarif_carries_a_security_severity_for_sorting() -> None:
    document = render_sarif(_results(_finding()))
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert float(rule["properties"]["security-severity"]) == pytest.approx(7.5)


def test_sarif_is_serialisable() -> None:
    document = render_sarif(_results(_finding(reach=_reachable())))
    assert json.loads(json.dumps(document))["version"] == "2.1.0"
