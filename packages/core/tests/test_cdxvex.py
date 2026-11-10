"""CycloneDX VEX.

The same conclusions as the OpenVEX document in the other format the ecosystem
reads, so these tests are mostly about where the two formats differ. Those
differences are the whole content of the module: a different justification
vocabulary, a different question asked by the state field, and components
carried inline.

Every document is validated against the official CycloneDX schema, because a
document a consumer's tooling rejects is worse than none: they have to work out
whether the rejection or the content is wrong.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from vexpath_core.cdxvex import (
    CODE_NOT_REACHABLE,
    CycloneDxVexError,
    VexMetadata,
    render,
    render_json,
    state_counts,
    validate,
)
from vexpath_core.enums import (
    ComponentScope,
    Confidence,
    EntryPointSource,
    ReachReason,
    ReachStatus,
    ScanMode,
    Severity,
    Verdict,
    VexJustification,
)
from vexpath_core.models.finding import (
    AdvisoryRef,
    ComponentRef,
    EntryPointInfo,
    Finding,
    ReachabilityResult,
)
from vexpath_core.models.results import ProjectRef, ScanResults

AUTHOR = VexMetadata(author="Example Org", product_id="pkg:pypi/my-service@1.0.0")
WHEN = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def _reach(status: ReachStatus, *, reason: ReachReason | None = None) -> ReachabilityResult:
    definitive = {
        ReachStatus.UNREACHABLE,
        ReachStatus.REACHABLE_CONFIRMED,
        ReachStatus.REACHABLE_POSSIBLE,
    }
    return ReachabilityResult(
        status=status,
        confidence=Confidence.HIGH,
        reason=reason or (None if status in definitive else ReachReason.NO_FIX_COMMIT),
        matched_symbols=("lib.danger",) if status.is_reachable else (),
        searched_symbols=("lib.danger", "lib.other"),
        via_dynamic_edges=status is ReachStatus.REACHABLE_POSSIBLE,
        entry_points=EntryPointInfo(source=EntryPointSource.CONFIG, count=4, items=("app",)),
        explanation="Nothing calls it.",
    )


def _finding(
    verdict: Verdict,
    *,
    status: ReachStatus | None = None,
    severity: Severity = Severity.HIGH,
    cvss: float | None = 7.5,
    advisory: str = "CVE-2026-0001",
    name: str = "lib",
    fixed_in: str | None = "2.0.0",
    suppressed_by: str | None = None,
    justification: VexJustification | None = None,
) -> Finding:
    return Finding(
        id="01",
        advisory=AdvisoryRef(
            id=advisory,
            summary="something went wrong",
            severity=severity,
            cvss_v3_score=cvss,
            aliases=("GHSA-aaaa-bbbb-cccc",),
        ),
        component=ComponentRef(
            purl=f"pkg:pypi/{name}@1.0.0",
            ecosystem="PyPI",
            name=name,
            version="1.0.0",
            direct=True,
            scope=ComponentScope.RUNTIME,
        ),
        verdict=verdict,
        reach=_reach(status) if status else None,
        justification=(
            justification
            if justification is not None
            else (
                VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
                if verdict is Verdict.NOT_AFFECTED
                else None
            )
        ),
        fixed_in=fixed_in,
        suppressed_by=suppressed_by,
    )


def _results(*findings: Finding, snapshot: str | None = "snap-1", slug: str | None = None):
    return ScanResults(
        schema_version="vexpath.results/1",
        core_version="0.0.1",
        generated_at=WHEN,
        mode=ScanMode.CLI,
        project=ProjectRef(slug=slug),
        advisory_snapshot_id=snapshot,
        findings=findings,
    )


CLEARED = _finding(Verdict.NOT_AFFECTED, status=ReachStatus.UNREACHABLE)
REACHABLE = _finding(
    Verdict.AFFECTED, status=ReachStatus.REACHABLE_CONFIRMED, advisory="CVE-2026-0002"
)
OPEN = _finding(
    Verdict.UNDER_INVESTIGATION, status=ReachStatus.SYMBOLS_UNKNOWN, advisory="CVE-2026-0003"
)


# --- The format's own schema ----------------------------------------------


def test_every_document_satisfies_the_official_schema() -> None:
    """A document a consumer's tooling rejects is worse than none."""
    validate(render_json(_results(CLEARED, REACHABLE, OPEN), AUTHOR))


def test_a_document_with_no_findings_still_validates() -> None:
    """A clean project should be able to publish that it is clean."""
    rendered = render_json(_results(), AUTHOR)
    validate(rendered)
    assert json.loads(rendered)["vulnerabilities"] == []


def test_the_document_declares_the_specification_and_the_tool() -> None:
    document = render(_results(CLEARED), AUTHOR)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["serialNumber"].startswith("urn:uuid:")
    assert document["metadata"]["tools"]["components"][0]["name"] == "vexpath"
    assert document["metadata"]["authors"] == [{"name": "Example Org"}]


def test_a_document_cannot_be_published_anonymously() -> None:
    with pytest.raises(CycloneDxVexError, match="author"):
        render(_results(CLEARED), VexMetadata(author="  "))


# --- Where the two formats differ -----------------------------------------


def test_the_justification_comes_from_cyclonedx_vocabulary_not_openvex() -> None:
    """The formats do not share these labels.

    Emitting OpenVEX's spelling here would produce a document that validates
    structurally and means nothing to a CycloneDX consumer.
    """
    analysis = render(_results(CLEARED), AUTHOR)["vulnerabilities"][0]["analysis"]
    assert analysis["justification"] == CODE_NOT_REACHABLE
    assert analysis["justification"] != "vulnerable_code_not_in_execute_path"


def test_a_cleared_finding_is_never_labelled_a_false_positive() -> None:
    """A finding that does not apply is not a mistake in the advisory.

    Calling it one would blame the advisory database for being right, and
    would tell a consumer the data is bad rather than that the code is unused.
    """
    states = {
        entry["analysis"]["state"]
        for entry in render(_results(CLEARED, REACHABLE, OPEN), AUTHOR)["vulnerabilities"]
    }
    assert "false_positive" not in states
    assert states == {"not_affected", "exploitable", "in_triage"}


def test_the_components_are_carried_inline_so_the_document_stands_alone() -> None:
    """Every bom-ref a vulnerability points at has to resolve."""
    document = render(_results(CLEARED, REACHABLE), AUTHOR)
    refs = {component["bom-ref"] for component in document["components"]}
    for entry in document["vulnerabilities"]:
        for affected in entry["affects"]:
            assert affected["ref"] in refs


def test_a_component_appearing_in_two_findings_is_listed_once() -> None:
    first = _finding(Verdict.NOT_AFFECTED, status=ReachStatus.UNREACHABLE, advisory="CVE-A")
    second = _finding(Verdict.NOT_AFFECTED, status=ReachStatus.UNREACHABLE, advisory="CVE-B")
    document = render(_results(first, second), AUTHOR)
    assert len(document["components"]) == 1
    assert len(document["vulnerabilities"]) == 2


def test_the_product_is_the_document_subject_and_not_the_dependency() -> None:
    document = render(_results(CLEARED), AUTHOR)
    assert document["metadata"]["component"]["bom-ref"] == "pkg:pypi/my-service@1.0.0"
    # The vulnerable dependency appears as an affected component, never as the
    # thing the document is about.
    assert document["components"][0]["purl"] == "pkg:pypi/lib@1.0.0"


def test_the_slug_names_the_product_when_nothing_else_does() -> None:
    document = render(_results(CLEARED, slug="org/service"), VexMetadata(author="A"))
    assert document["metadata"]["component"]["bom-ref"] == "pkg:generic/org/service"


# --- What a record says ---------------------------------------------------


def test_a_cleared_record_carries_the_evidence_for_it() -> None:
    detail = render(_results(CLEARED), AUTHOR)["vulnerabilities"][0]["analysis"]["detail"]
    assert "Nothing calls it." in detail
    assert "lib.danger" in detail
    assert "4 entry point(s)" in detail
    assert "Confidence: high" in detail
    assert "snapshot snap-1" in detail


def test_a_record_against_a_live_corpus_says_it_is_not_reproducible() -> None:
    detail = render(_results(CLEARED, snapshot=None), AUTHOR)["vulnerabilities"][0]["analysis"][
        "detail"
    ]
    assert "not reproducible" in detail


def test_an_affected_record_says_what_the_response_is() -> None:
    analysis = render(_results(REACHABLE), AUTHOR)["vulnerabilities"][0]["analysis"]
    assert analysis["state"] == "exploitable"
    assert analysis["response"] == ["update"]


def test_an_affected_record_with_no_fix_says_so_instead() -> None:
    """Calling unavailable work an upgrade would mislead."""
    finding = _finding(Verdict.AFFECTED, status=ReachStatus.REACHABLE_CONFIRMED, fixed_in=None)
    analysis = render(_results(finding), AUTHOR)["vulnerabilities"][0]["analysis"]
    assert analysis["response"] == ["will_not_fix"]


def test_an_open_record_says_why_it_is_open() -> None:
    detail = render(_results(OPEN), AUTHOR)["vulnerabilities"][0]["analysis"]["detail"]
    assert "Nothing calls it." in detail


def test_a_finding_with_no_analysis_says_reachability_did_not_run() -> None:
    finding = _finding(Verdict.UNDER_INVESTIGATION)
    detail = render(_results(finding), AUTHOR)["vulnerabilities"][0]["analysis"]["detail"]
    assert "did not run" in detail


def test_a_rating_keeps_the_severity_even_with_no_score() -> None:
    """A consumer filtering on severity should not lose a finding for want of
    a number."""
    finding = _finding(Verdict.NOT_AFFECTED, status=ReachStatus.UNREACHABLE, cvss=None)
    rating = render(_results(finding), AUTHOR)["vulnerabilities"][0]["ratings"][0]
    assert rating["severity"] == "high"
    assert "score" not in rating


def test_a_rating_carries_the_score_and_names_the_method() -> None:
    rating = render(_results(CLEARED), AUTHOR)["vulnerabilities"][0]["ratings"][0]
    assert rating["score"] == 7.5
    assert rating["method"] == "CVSSv31"


def test_severity_uses_the_formats_own_lower_case_vocabulary() -> None:
    finding = _finding(
        Verdict.NOT_AFFECTED, status=ReachStatus.UNREACHABLE, severity=Severity.UNKNOWN
    )
    assert (
        render(_results(finding), AUTHOR)["vulnerabilities"][0]["ratings"][0]["severity"]
        == "unknown"
    )


def test_aliases_are_recorded_so_a_consumer_can_match_on_any_of_them() -> None:
    references = render(_results(CLEARED), AUTHOR)["vulnerabilities"][0]["references"]
    assert references[0]["id"] == "GHSA-aaaa-bbbb-cccc"


# --- Claims it is not entitled to make ------------------------------------


def test_the_model_refuses_a_clearance_without_proof_in_the_first_place() -> None:
    """The first of two layers, and the one that normally fires."""
    with pytest.raises(ValueError, match="only 'unreachable' may suppress"):
        _finding(Verdict.NOT_AFFECTED, status=ReachStatus.SYMBOLS_UNKNOWN)


def test_a_clearance_without_a_proven_unreachable_result_is_refused() -> None:
    """``code_not_reachable`` is the only value this analysis earns.

    The others assert that the code is absent, that configuration or an
    environment is required, or that something protects it, and none of those
    was tested.

    Built with ``model_construct`` at both levels to skip validation, because
    the finding model refuses this combination and the results model refuses it
    again. That is three layers in total and this test reaches past the first
    two on purpose, to prove the renderer would not publish such a claim even
    if they were ever relaxed.
    """
    sound = _finding(Verdict.NOT_AFFECTED, status=ReachStatus.UNREACHABLE)
    unsound = Finding.model_construct(
        **{**sound.__dict__, "reach": _reach(ReachStatus.SYMBOLS_UNKNOWN)}
    )
    results = ScanResults.model_construct(**{**_results().__dict__, "findings": (unsound,)})
    with pytest.raises(CycloneDxVexError, match="only thing this analysis can justify"):
        render(results, AUTHOR)


def test_a_human_suppression_is_the_one_exception() -> None:
    """A person asserted it and stands behind it; the detail names them."""
    finding = _finding(
        Verdict.NOT_AFFECTED,
        status=ReachStatus.SYMBOLS_UNKNOWN,
        suppressed_by="waiver-17",
    )
    analysis = render(_results(finding), AUTHOR)["vulnerabilities"][0]["analysis"]
    assert analysis["justification"] == CODE_NOT_REACHABLE
    assert "waiver-17" in analysis["detail"]


# --- Determinism ----------------------------------------------------------


def test_the_same_results_produce_the_same_bytes() -> None:
    results = _results(CLEARED, REACHABLE)
    assert render_json(results, AUTHOR) == render_json(results, AUTHOR)


def test_the_serial_number_is_derived_from_the_content() -> None:
    """Derived rather than random, so two documents can be compared."""
    first = render(_results(CLEARED), AUTHOR)["serialNumber"]
    again = render(_results(CLEARED), AUTHOR)["serialNumber"]
    different = render(_results(REACHABLE), AUTHOR)["serialNumber"]
    assert first == again
    assert first != different


def test_records_are_ordered_worst_first() -> None:
    low = _finding(
        Verdict.NOT_AFFECTED,
        status=ReachStatus.UNREACHABLE,
        severity=Severity.LOW,
        advisory="CVE-2026-9999",
    )
    critical = _finding(
        Verdict.NOT_AFFECTED,
        status=ReachStatus.UNREACHABLE,
        severity=Severity.CRITICAL,
        advisory="CVE-2026-0001",
    )
    document = render(_results(low, critical), AUTHOR)
    assert [entry["id"] for entry in document["vulnerabilities"]] == [
        "CVE-2026-0001",
        "CVE-2026-9999",
    ]


def test_states_can_be_counted_for_a_summary() -> None:
    document = render(_results(CLEARED, REACHABLE, OPEN), AUTHOR)
    assert state_counts(document) == {"exploitable": 1, "in_triage": 1, "not_affected": 1}
