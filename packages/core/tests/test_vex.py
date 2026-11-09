"""OpenVEX generation.

The document is the product's output, so these tests are mostly about claims:
which ones it is entitled to make, whose product it is making them about, and
whether a reader can check them. The formatting is incidental; the modelling is
not.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from vexpath_core.enums import (
    ComponentScope,
    Confidence,
    EdgeKind,
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
    CallPathStep,
    ComponentRef,
    EntryPointInfo,
    Finding,
    GraphStats,
    ReachabilityResult,
)
from vexpath_core.models.results import ProjectRef, ScanResults
from vexpath_core.vex import (
    OPENVEX_CONTEXT,
    VexError,
    VexIdentity,
    document_sha256,
    render,
    render_json,
    statement_counts,
)

AUTHOR = VexIdentity(author="Example Org", product_id="pkg:pypi/my-service@1.0.0")
WHEN = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def _component(name: str = "urllib3", version: str = "1.26.17") -> ComponentRef:
    return ComponentRef(
        purl=f"pkg:pypi/{name}@{version}",
        ecosystem="PyPI",
        name=name,
        version=version,
        direct=False,
        scope=ComponentScope.RUNTIME,
    )


def _reach(
    status: ReachStatus,
    *,
    confidence: Confidence = Confidence.HIGH,
    reason: ReachReason | None = None,
) -> ReachabilityResult:
    return ReachabilityResult(
        status=status,
        confidence=confidence,
        reason=reason,
        matched_symbols=(
            ("urllib3.poolmanager.PoolManager.urlopen",) if status.is_reachable else ()
        ),
        searched_symbols=("urllib3.poolmanager.PoolManager.urlopen",),
        shortest_path=(
            (
                CallPathStep(
                    symbol="app.main", file="app/main.py", line=1, edge_kind=EdgeKind.STATIC
                ),
                CallPathStep(
                    symbol="urllib3.poolmanager.PoolManager.urlopen",
                    file="urllib3/poolmanager.py",
                    line=400,
                    edge_kind=EdgeKind.STATIC,
                ),
            )
            if status.is_reachable
            else ()
        ),
        # The model refuses a possible verdict that does not admit it relied on
        # an unresolved edge, which is the whole meaning of the status.
        via_dynamic_edges=status is ReachStatus.REACHABLE_POSSIBLE,
        entry_points=EntryPointInfo(source=EntryPointSource.CONFIG, count=3, items=("app.main",)),
        graph_stats=GraphStats(
            first_party_nodes=120,
            first_party_edges=800,
            linked_packages=7,
            unresolved_call_ratio=0.12,
        ),
        explanation="Nothing calls it.",
    )


def _finding(
    verdict: Verdict,
    *,
    reach: ReachabilityResult | None = None,
    justification: VexJustification | None = None,
    fixed_in: str | None = "2.0.0",
    advisory_id: str = "CVE-2023-45803",
    severity: Severity = Severity.HIGH,
    component: ComponentRef | None = None,
    suppressed_by: str | None = None,
) -> Finding:
    return Finding(
        id="01",
        advisory=AdvisoryRef(
            id=advisory_id,
            summary="urllib3 keeps the body after a redirect",
            severity=severity,
            aliases=("GHSA-g4mx-q9vg-27p4",),
        ),
        component=component or _component(),
        verdict=verdict,
        justification=justification,
        reach=reach,
        fixed_in=fixed_in,
        suppressed_by=suppressed_by,
    )


def _results(
    *findings: Finding, slug: str | None = None, snapshot: str | None = "snap-1"
) -> ScanResults:
    return ScanResults(
        schema_version="vexpath.results/1",
        core_version="0.0.1",
        generated_at=WHEN,
        mode=ScanMode.CLI,
        project=ProjectRef(slug=slug),
        advisory_snapshot_id=snapshot,
        findings=findings,
    )


def _cleared() -> Finding:
    return _finding(
        Verdict.NOT_AFFECTED,
        reach=_reach(ReachStatus.UNREACHABLE),
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    )


# --- Whose product is this about ------------------------------------------


def test_the_product_is_what_you_ship_and_the_dependency_is_a_subcomponent() -> None:
    """The rule most tools get wrong.

    A statement whose product is the vulnerable dependency says "urllib3 is not
    affected by its own advisory", which is false and not ours to say.
    """
    document = render(_results(_cleared()), AUTHOR)
    product = document["statements"][0]["products"][0]

    assert product["@id"] == "pkg:pypi/my-service@1.0.0"
    assert product["subcomponents"] == [{"@id": "pkg:pypi/urllib3@1.26.17"}]


def test_the_project_slug_identifies_the_product_when_nothing_else_does() -> None:
    document = render(_results(_cleared(), slug="my-org/my-service"), VexIdentity(author="A"))
    assert document["statements"][0]["products"][0]["@id"] == "pkg:generic/my-org/my-service"


def test_an_unidentified_product_says_so_rather_than_inventing_one() -> None:
    """A product identifier nobody set cannot be matched to an inventory."""
    document = render(_results(_cleared()), VexIdentity(author="A"))
    assert document["statements"][0]["products"][0]["@id"] == "urn:vexpath:product:unidentified"


def test_a_document_cannot_be_published_anonymously() -> None:
    """Its whole purpose is that a consumer decides whether to believe it."""
    with pytest.raises(VexError, match="author"):
        render(_results(_cleared()), VexIdentity(author="   "))


# --- Which claims it is entitled to make ----------------------------------


def test_a_cleared_finding_uses_the_justification_reachability_earns() -> None:
    document = render(_results(_cleared()), AUTHOR)
    statement = document["statements"][0]
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "vulnerable_code_not_in_execute_path"


@pytest.mark.parametrize(
    "justification",
    [
        VexJustification.COMPONENT_NOT_PRESENT,
        VexJustification.VULNERABLE_CODE_NOT_PRESENT,
        VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
        VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
    ],
)
def test_no_other_justification_may_be_asserted(justification: VexJustification) -> None:
    """Each of these is a different claim with different evidence.

    Reachability establishes that the vulnerable code is not in the execute
    path. It does not establish that the component is absent, that the code was
    removed, that an adversary cannot reach it, or that something mitigates it.
    """
    finding = _finding(
        Verdict.NOT_AFFECTED,
        reach=_reach(ReachStatus.UNREACHABLE),
        justification=justification,
    )
    with pytest.raises(VexError, match="does not establish"):
        render(_results(finding), AUTHOR)


def test_a_human_suppression_keeps_its_own_justification() -> None:
    """A person asserting a mitigation is the one case we did not test.

    They stand behind it, the document records which justification they chose,
    and the suppression identifier is in the results for anyone checking.
    """
    finding = _finding(
        Verdict.NOT_AFFECTED,
        reach=_reach(ReachStatus.UNREACHABLE),
        justification=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
        suppressed_by="waiver-17",
    )
    statement = render(_results(finding), AUTHOR)["statements"][0]
    assert statement["justification"] == "inline_mitigations_already_exist"


def test_a_cleared_statement_carries_the_evidence_for_it() -> None:
    """The specification would accept a bare justification.

    A consumer deciding whether to trust someone else's "not affected" needs
    to see what was searched for and from where. An unexplained clearance is
    one nobody can check.
    """
    statement = render(_results(_cleared()), AUTHOR)["statements"][0]
    impact = statement["impact_statement"]

    assert "urllib3.poolmanager.PoolManager.urlopen" in impact
    assert "3 entry point(s)" in impact
    assert "config" in impact
    assert "linked dependency package(s)" in impact
    assert "Confidence: high" in impact
    assert "snapshot snap-1" in impact


def test_a_clearance_against_a_live_corpus_says_it_is_not_reproducible() -> None:
    document = render(_results(_cleared(), snapshot=None), AUTHOR)
    assert "not reproducible" in document["statements"][0]["impact_statement"]


# --- Affected and open statements -----------------------------------------


def test_an_affected_statement_says_what_to_do() -> None:
    """Required by the specification, and the only actionable field there is."""
    finding = _finding(Verdict.AFFECTED, reach=_reach(ReachStatus.REACHABLE_CONFIRMED))
    statement = render(_results(finding), AUTHOR)["statements"][0]

    assert statement["status"] == "affected"
    assert "Upgrade urllib3 to 2.0.0" in statement["action_statement"]
    assert "app.main -> urllib3.poolmanager.PoolManager.urlopen" in statement["action_statement"]
    assert statement["action_statement_timestamp"]


def test_an_affected_finding_with_no_fix_says_that_instead() -> None:
    finding = _finding(
        Verdict.AFFECTED, reach=_reach(ReachStatus.REACHABLE_CONFIRMED), fixed_in=None
    )
    action = render(_results(finding), AUTHOR)["statements"][0]["action_statement"]
    assert "No fixed version" in action
    assert "mitigate in place" in action


def test_a_possibly_reachable_finding_says_the_path_was_not_resolved() -> None:
    finding = _finding(Verdict.AFFECTED, reach=_reach(ReachStatus.REACHABLE_POSSIBLE))
    action = render(_results(finding), AUTHOR)["statements"][0]["action_statement"]
    assert "could not resolve precisely" in action


def test_an_open_finding_says_why_it_is_open() -> None:
    """This is what stops "under investigation" being read as a shrug."""
    finding = _finding(
        Verdict.UNDER_INVESTIGATION,
        reach=_reach(
            ReachStatus.SYMBOLS_UNKNOWN,
            confidence=Confidence.LOW,
            reason=ReachReason.PACKAGE_NOT_ANALYSED,
        ),
    )
    statement = render(_results(finding), AUTHOR)["statements"][0]

    assert statement["status"] == "under_investigation"
    assert "package_not_analysed" in statement["status_notes"]


def test_an_open_finding_with_no_analysis_says_that_too() -> None:
    finding = _finding(Verdict.UNDER_INVESTIGATION)
    notes = render(_results(finding), AUTHOR)["statements"][0]["status_notes"]
    assert "did not run" in notes


def test_open_findings_can_be_left_out_but_are_included_by_default() -> None:
    """An absent statement reads as "not an issue", which it is not."""
    results = _results(_cleared(), _finding(Verdict.UNDER_INVESTIGATION, advisory_id="CVE-X"))

    assert len(render(results, AUTHOR)["statements"]) == 2
    trimmed = render(results, AUTHOR, include_under_investigation=False)
    assert [s["status"] for s in trimmed["statements"]] == ["not_affected"]


# --- The document itself --------------------------------------------------


def test_the_document_declares_the_specification_it_follows() -> None:
    document = render(_results(_cleared()), AUTHOR)
    assert document["@context"] == OPENVEX_CONTEXT
    assert document["tooling"].startswith("vexpath/")
    assert document["author"] == "Example Org"
    assert document["role"]
    assert document["version"] == 1
    assert document["timestamp"] == "2026-11-09T12:00:00+00:00"


def test_a_vulnerability_carries_its_aliases_and_description() -> None:
    """A consumer matching on a GHSA identifier must still find the statement."""
    vulnerability = render(_results(_cleared()), AUTHOR)["statements"][0]["vulnerability"]
    assert vulnerability["name"] == "CVE-2023-45803"
    assert vulnerability["aliases"] == ["GHSA-g4mx-q9vg-27p4"]
    assert "redirect" in vulnerability["description"]


def test_the_same_results_produce_the_same_bytes() -> None:
    """What lets two documents be diffed, and makes a hash worth attesting."""
    results = _results(_cleared())
    first = render_json(results, AUTHOR)
    second = render_json(results, AUTHOR)

    assert first == second
    assert document_sha256(first) == document_sha256(second)
    assert first.endswith("\n")


def test_the_identifier_is_derived_from_the_content() -> None:
    document = render(_results(_cleared()), AUTHOR)
    assert document["@id"].startswith("https://openvex.dev/docs/vexpath-")

    # A different conclusion is a different document.
    other = render(
        _results(_finding(Verdict.AFFECTED, reach=_reach(ReachStatus.REACHABLE_CONFIRMED))), AUTHOR
    )
    assert other["@id"] != document["@id"]


def test_an_explicit_identifier_is_honoured() -> None:
    document = render(_results(_cleared()), AUTHOR, document_id="https://example.org/vex/1")
    assert document["@id"] == "https://example.org/vex/1"


def test_statements_are_ordered_worst_first_and_stably() -> None:
    low = _finding(
        Verdict.NOT_AFFECTED,
        reach=_reach(ReachStatus.UNREACHABLE),
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        advisory_id="CVE-2026-0002",
        severity=Severity.LOW,
    )
    critical = _finding(
        Verdict.NOT_AFFECTED,
        reach=_reach(ReachStatus.UNREACHABLE),
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        advisory_id="CVE-2026-0001",
        severity=Severity.CRITICAL,
    )
    document = render(_results(low, critical), AUTHOR)
    assert [s["vulnerability"]["name"] for s in document["statements"]] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]


def test_statement_counts_summarise_a_document() -> None:
    results = _results(_cleared(), _finding(Verdict.UNDER_INVESTIGATION, advisory_id="CVE-X"))
    counts = statement_counts(render(results, AUTHOR))
    assert counts == {"not_affected": 1, "under_investigation": 1}


def test_a_document_with_no_findings_is_still_a_valid_document() -> None:
    """A clean project should be able to publish that it is clean."""
    document = render(_results(), AUTHOR)
    assert document["statements"] == []
    assert document["@id"]
    assert json.loads(render_json(_results(), AUTHOR))["statements"] == []


def test_every_statement_has_the_fields_the_specification_requires() -> None:
    results = _results(
        _cleared(),
        _finding(
            Verdict.AFFECTED, reach=_reach(ReachStatus.REACHABLE_CONFIRMED), advisory_id="CVE-A"
        ),
        _finding(Verdict.UNDER_INVESTIGATION, advisory_id="CVE-B"),
    )
    for statement in render(results, AUTHOR)["statements"]:
        assert statement["vulnerability"]["name"]
        assert statement["products"]
        assert statement["status"]
        assert statement["timestamp"]
        if statement["status"] == "not_affected":
            # One of justification or impact_statement is required; both are
            # given, because a justification alone cannot be checked.
            assert statement["justification"]
            assert statement["impact_statement"]
        if statement["status"] == "affected":
            assert statement["action_statement"]
