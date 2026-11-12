"""The build gate.

A gate is only worth having if it is predictable, so these tests are about the
two ways a gate goes wrong: it passes something it should have stopped, or it
stops a build for a reason nobody can act on.

The convention that shapes all of it: an expression evaluates to true when the
build must *fail*. Stated the other way round, every mistake in a policy would
turn into a green build.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vexpath_core.enums import (
    ComponentScope,
    Confidence,
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
    Finding,
    ReachabilityResult,
)
from vexpath_core.models.results import ProjectRef, ScanResults
from vexpath_core.policy import (
    DEFAULT_PRESET,
    PRESETS,
    PolicyError,
    build_context,
    compile_policy,
    evaluate,
    explain,
    needs_attention_expression,
    severity_at_least,
)

WHEN = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def _reach(
    status: ReachStatus,
    *,
    confidence: Confidence = Confidence.HIGH,
    reason: ReachReason | None = None,
) -> ReachabilityResult:
    # The model requires a reason for every non-definitive status, which is the
    # rule that stops an unexplained "unknown" existing at all.
    needs_reason = status not in {
        ReachStatus.UNREACHABLE,
        ReachStatus.REACHABLE_CONFIRMED,
        ReachStatus.REACHABLE_POSSIBLE,
    }
    return ReachabilityResult(
        status=status,
        confidence=confidence,
        reason=reason or (ReachReason.NO_FIX_COMMIT if needs_reason else None),
        matched_symbols=("lib.danger",) if status.is_reachable else (),
        searched_symbols=("lib.danger",),
        via_dynamic_edges=status is ReachStatus.REACHABLE_POSSIBLE,
        explanation="x",
    )


def _finding(
    verdict: Verdict,
    *,
    severity: Severity = Severity.HIGH,
    kev: bool = False,
    epss: float | None = None,
    status: ReachStatus | None = None,
    advisory: str = "CVE-2026-0001",
    name: str = "lib",
    direct: bool = True,
    scope: ComponentScope = ComponentScope.RUNTIME,
    fixed_in: str | None = "2.0.0",
    suppressed_by: str | None = None,
) -> Finding:
    return Finding(
        id=f"id-{advisory}",
        advisory=AdvisoryRef(id=advisory, severity=severity, kev=kev, epss_score=epss),
        component=ComponentRef(
            purl=f"pkg:pypi/{name}@1.0.0",
            ecosystem="PyPI",
            name=name,
            version="1.0.0",
            direct=direct,
            scope=scope,
        ),
        verdict=verdict,
        reach=_reach(status) if status else None,
        justification=(
            VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
            if verdict is Verdict.NOT_AFFECTED
            else None
        ),
        fixed_in=fixed_in,
        suppressed_by=suppressed_by,
    )


def _results(*findings: Finding, mode: ScanMode = ScanMode.CLI, slug: str | None = None):
    return ScanResults(
        schema_version="vexpath.results/1",
        core_version="0.0.1",
        generated_at=WHEN,
        mode=mode,
        project=ProjectRef(slug=slug, git_ref="refs/heads/main"),
        advisory_snapshot_id="snap-1",
        findings=findings,
    )


REACHABLE_HIGH = _finding(Verdict.AFFECTED, status=ReachStatus.REACHABLE_CONFIRMED)
POSSIBLE_HIGH = _finding(
    Verdict.AFFECTED, status=ReachStatus.REACHABLE_POSSIBLE, advisory="CVE-2026-0002"
)
CLEARED = _finding(Verdict.NOT_AFFECTED, status=ReachStatus.UNREACHABLE, advisory="CVE-2026-0003")
OPEN_MEDIUM = _finding(
    Verdict.UNDER_INVESTIGATION,
    severity=Severity.MEDIUM,
    status=ReachStatus.SYMBOLS_UNKNOWN,
    advisory="CVE-2026-0004",
)
KEV_MEDIUM_OPEN = _finding(
    Verdict.UNDER_INVESTIGATION, severity=Severity.MEDIUM, kev=True, advisory="CVE-2026-0005"
)
KEV_CLEARED = _finding(
    Verdict.NOT_AFFECTED, kev=True, status=ReachStatus.UNREACHABLE, advisory="CVE-2026-0006"
)


def _passes(policy: str, *findings: Finding) -> bool:
    return evaluate(_results(*findings), policy).passed


# --- The presets, case by case --------------------------------------------


def test_the_default_is_the_one_the_product_exists_to_make_possible() -> None:
    assert DEFAULT_PRESET == "balanced"


def test_balanced_fails_on_proven_reachable_and_passes_the_rest() -> None:
    """The whole argument for reachability analysis, as a gate."""
    assert not _passes("balanced", REACHABLE_HIGH)
    assert _passes("balanced", CLEARED)
    # A possible path is reported but does not fail the build on its own:
    # gating on every unresolved call would gate on almost everything.
    assert _passes("balanced", POSSIBLE_HIGH)
    assert _passes("balanced", OPEN_MEDIUM)


def test_balanced_fails_on_anything_known_to_be_exploited() -> None:
    """Observed exploitation outranks any reachability answer."""
    assert not _passes("balanced", KEV_MEDIUM_OPEN)


def test_balanced_still_respects_a_proven_clearance_for_a_kev_advisory() -> None:
    """If the vulnerable code cannot run, it cannot be exploited here.

    This is the one place the gate trusts the analysis over the catalogue, and
    it is deliberate: KEV says the vulnerability is exploited somewhere, not
    that this project executes the code.
    """
    assert _passes("balanced", KEV_CLEARED)


def test_strict_ignores_reachability_entirely() -> None:
    """For a team that has not decided how much it trusts the analysis."""
    assert not _passes("strict", REACHABLE_HIGH)
    assert not _passes("strict", POSSIBLE_HIGH)
    assert _passes("strict", CLEARED)
    assert _passes("strict", _finding(Verdict.AFFECTED, severity=Severity.MEDIUM))


def test_kev_only_fails_on_nothing_else() -> None:
    assert _passes("kev-only", REACHABLE_HIGH)
    assert not _passes("kev-only", KEV_MEDIUM_OPEN)


def test_nothing_outstanding_fails_on_anything_needing_a_human() -> None:
    assert not _passes("nothing-outstanding", OPEN_MEDIUM)
    assert not _passes("nothing-outstanding", REACHABLE_HIGH)
    assert _passes("nothing-outstanding", CLEARED)


def test_report_only_is_a_decision_rather_than_an_omission() -> None:
    """Named so a configuration can say it chose not to gate."""
    assert _passes("report-only", REACHABLE_HIGH, KEV_MEDIUM_OPEN, OPEN_MEDIUM)


def test_a_clean_scan_passes_every_preset() -> None:
    for name in PRESETS:
        assert evaluate(_results(), name).passed, name


def test_every_preset_is_described() -> None:
    """A preset nobody can explain is one nobody should adopt."""
    for name in PRESETS:
        assert explain(name), name


def test_every_preset_compiles() -> None:
    for name in PRESETS:
        assert compile_policy(name).name == name


# --- What a failure tells you ---------------------------------------------


def test_a_failure_names_the_rule_the_finding_and_why() -> None:
    """A gate that reports only "failed" has to be reverse-engineered."""
    outcome = evaluate(_results(REACHABLE_HIGH, CLEARED), "balanced")

    assert not outcome.passed
    assert outcome.name == "balanced"
    assert len(outcome.violations) == 1
    violation = outcome.violations[0]
    assert violation.rule == "balanced"
    assert violation.advisory_id == "CVE-2026-0001"
    assert violation.component == "pkg:pypi/lib@1.0.0"
    assert violation.finding_id == "id-CVE-2026-0001"
    assert "HIGH CVE-2026-0001" in violation.message
    assert "reachable_confirmed" in violation.message
    assert "fixed in 2.0.0" in violation.message


def test_a_kev_failure_says_it_is_exploited_in_the_wild() -> None:
    outcome = evaluate(_results(KEV_MEDIUM_OPEN), "balanced")
    assert "exploited in the wild" in outcome.violations[0].message


def test_a_passing_policy_reports_no_violations() -> None:
    outcome = evaluate(_results(CLEARED), "balanced")
    assert outcome.passed
    assert outcome.violations == ()


def test_a_failure_no_single_finding_explains_says_so() -> None:
    """An expression can fail on the set rather than on any one row.

    Leaving the report blank in that case would be the least helpful possible
    answer, so it says what happened instead.
    """
    outcome = evaluate(
        _results(CLEARED, OPEN_MEDIUM), "counts.under_investigation > 0 && size(findings) > 1"
    )
    assert not outcome.passed
    assert len(outcome.violations) == 1
    assert "as a whole" in outcome.violations[0].message


# --- What a policy can read -----------------------------------------------


def test_the_context_exposes_every_field_the_documentation_promises() -> None:
    context = build_context(_results(REACHABLE_HIGH, slug="my-org/service"))
    assert set(context) == {"findings", "scan", "project", "counts"}

    # Checked through CEL rather than by inspecting the mapping, because what
    # matters is that an expression can read them.
    for expression in (
        'findings[0].advisory == "CVE-2026-0001"',
        'findings[0].component == "lib"',
        'findings[0].purl == "pkg:pypi/lib@1.0.0"',
        'findings[0].ecosystem == "PyPI"',
        'findings[0].version == "1.0.0"',
        'findings[0].severity == "HIGH"',
        "findings[0].severity_rank > 0",
        "findings[0].cvss == 0.0",
        "findings[0].epss == 0.0",
        "findings[0].kev == false",
        'findings[0].verdict == "affected"',
        'findings[0].justification == ""',
        'findings[0].fixed_in == "2.0.0"',
        "findings[0].has_fix",
        "findings[0].age_days == 0",
        'findings[0].scope == "runtime"',
        "findings[0].direct",
        "!findings[0].suppressed",
        "findings[0].reach.analysed",
        'findings[0].reach.status == "reachable_confirmed"',
        'findings[0].reach.reason == ""',
        'findings[0].reach.confidence == "high"',
        "findings[0].reach.confidence_rank > 0",
        "findings[0].reach.reachable",
        "findings[0].reach.path_length == 0",
        "!findings[0].reach.via_dynamic_edges",
        'scan.mode == "cli"',
        'scan.git_ref == "refs/heads/main"',
        "scan.reproducible",
        'scan.snapshot == "snap-1"',
        "counts.affected == 1",
    ):
        # The expression is written to be true of this finding, and a true
        # expression fails the build, so a passing result means the field was
        # not readable as documented.
        assert not _passes(expression, REACHABLE_HIGH), expression

    # The slug needs results that carry one, so it is checked on its own.
    slugged = _results(REACHABLE_HIGH, slug="my-org/service")
    assert not evaluate(slugged, 'project.slug == "my-org/service"').passed


def test_a_policy_can_tell_not_reachable_from_never_looked() -> None:
    """Without this a gate silently treats unanalysed as safe."""
    unanalysed = _finding(Verdict.UNDER_INVESTIGATION, advisory="CVE-2026-0007")
    assert not _passes("findings.exists(f, !f.reach.analysed)", unanalysed)
    assert _passes("findings.exists(f, !f.reach.analysed)", CLEARED)


def test_no_field_is_null_so_a_reasonable_expression_cannot_error() -> None:
    """A comparison against a missing field would break the build."""
    bare = _finding(Verdict.UNDER_INVESTIGATION, fixed_in=None, epss=None, advisory="CVE-2026-0008")
    assert _passes('findings.exists(f, f.fixed_in == "9.9.9")', bare)
    assert _passes("findings.exists(f, f.epss > 0.5)", bare)
    assert _passes('findings.exists(f, f.reach.status == "unreachable")', bare)


def test_a_policy_cannot_read_a_clock_or_the_environment() -> None:
    """The same results and policy must give the same answer anywhere."""
    with pytest.raises(PolicyError):
        evaluate(_results(REACHABLE_HIGH), 'now > timestamp("2020-01-01T00:00:00Z")')


def test_the_same_results_give_the_same_answer_twice() -> None:
    results = _results(REACHABLE_HIGH, CLEARED, KEV_MEDIUM_OPEN)
    first = evaluate(results, "balanced")
    second = evaluate(results, "balanced")
    assert first == second


# --- Writing a policy by hand ---------------------------------------------


def test_a_custom_expression_is_accepted_and_named() -> None:
    compiled = compile_policy('findings.exists(f, f.component == "lib")')
    assert compiled.name == "custom"
    assert not compiled.evaluate(_results(REACHABLE_HIGH)).passed


def test_a_policy_can_be_given_a_name() -> None:
    compiled = compile_policy("findings.size() > 0", name="release-branch")
    assert compiled.name == "release-branch"
    assert compiled.evaluate(_results(REACHABLE_HIGH)).violations[0].rule == "release-branch"


def test_a_malformed_expression_is_refused_with_the_position() -> None:
    """A policy is written by hand, so the common failure is a typo."""
    with pytest.raises(PolicyError, match="not valid CEL"):
        compile_policy("findings.exists(f, f.verdict ===")


def test_an_expression_that_is_not_a_boolean_is_refused() -> None:
    """Anything else would make "truthy" the gate, which nobody intended."""
    with pytest.raises(PolicyError, match="rather than a boolean"):
        evaluate(_results(REACHABLE_HIGH), "size(findings)")


def test_an_empty_policy_is_refused_rather_than_passing_everything() -> None:
    """Silence must not be the same as a decision not to gate."""
    with pytest.raises(PolicyError, match="report-only"):
        compile_policy("   ")


def test_an_unknown_field_fails_rather_than_passing() -> None:
    """The dangerous direction is a typo that makes a gate always pass."""
    with pytest.raises(PolicyError):
        evaluate(_results(REACHABLE_HIGH), 'findings.exists(f, f.verdikt == "affected")')


# --- Helpers --------------------------------------------------------------


def test_a_severity_threshold_can_be_generated() -> None:
    fragment = severity_at_least(Severity.HIGH)
    assert "CRITICAL" in fragment
    assert "HIGH" in fragment
    assert "MEDIUM" not in fragment
    # UNKNOWN has rank zero and is excluded: it is an absence of information,
    # not a severity below the threshold.
    assert "UNKNOWN" not in fragment
    assert not _passes(f"findings.exists(f, {fragment})", REACHABLE_HIGH)


def test_the_needs_attention_expression_matches_what_a_report_shows() -> None:
    expression = needs_attention_expression()
    assert not _passes(expression, REACHABLE_HIGH)
    assert not _passes(expression, OPEN_MEDIUM)
    assert _passes(expression, CLEARED)


# --- The examples in the documentation have to be real --------------------


def test_every_cel_example_in_the_docs_uses_fields_that_exist() -> None:
    """A policy naming a field that does not exist never fires.

    CEL compiles an unknown field without complaint, so
    ``f.reachable == "confirmed"`` -- the shape documented in
    docs/00-blueprint.md until 2026-11-12, where the field is really
    ``f.reach.reachable`` and is a boolean -- produced a policy that passed
    every scan. For a build gate that is the worst available failure: it
    looks installed, it reports success, and it is not gating anything.

    So every ``f.<field>`` written in the documentation is checked against
    the context the evaluator actually builds.
    """
    import re
    from pathlib import Path

    from vexpath_core.policy import FINDING_FIELDS, REACH_FIELDS

    docs = Path(__file__).resolve().parents[3] / "docs"
    problems: list[str] = []

    for path in sorted(docs.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"\bf\.([a-z_]+)(?:\.([a-z_]+))?", text):
            first, second = match.group(1), match.group(2)
            where = f"{path.name}: f.{first}" + (f".{second}" if second else "")
            if first not in FINDING_FIELDS:
                problems.append(f"{where} -- no such finding field")
            elif second is not None and first == "reach" and second not in REACH_FIELDS:
                problems.append(f"{where} -- no such reach field")

    assert not problems, "documented policy examples name fields that do not exist: " + "; ".join(
        problems
    )


# --- "not reachable" is not "nobody could look" ---------------------------


@pytest.mark.parametrize(
    ("status", "conclusive"),
    [
        (ReachStatus.REACHABLE_CONFIRMED, True),
        (ReachStatus.REACHABLE_POSSIBLE, True),
        (ReachStatus.UNREACHABLE, True),
        (ReachStatus.SYMBOLS_UNKNOWN, False),
        (ReachStatus.GRAPH_INCOMPLETE, False),
    ],
)
def test_only_an_answer_counts_as_conclusive(status: ReachStatus, conclusive: bool) -> None:
    assert status.is_conclusive is conclusive


@pytest.mark.parametrize(
    ("status", "should_fail"),
    [
        # Reachable: the vulnerable code can run.
        (ReachStatus.REACHABLE_CONFIRMED, True),
        (ReachStatus.REACHABLE_POSSIBLE, True),
        # Cleared with evidence: present, traversed, no path.
        (ReachStatus.UNREACHABLE, False),
        # Nobody could look, which must not read as safe.
        (ReachStatus.SYMBOLS_UNKNOWN, True),
        (ReachStatus.GRAPH_INCOMPLETE, True),
    ],
)
def test_the_honest_gate_refuses_what_it_could_not_clear(
    status: ReachStatus, should_fail: bool
) -> None:
    """``reachable || !conclusive`` is the expression this project recommends.

    It was ``reachable || !analysed`` until 2026-11-12, which passed
    ``symbols_unknown``: reachability *ran* for those findings, so
    ``analysed`` was true. A build gate written that way reports success on
    findings nobody could clear -- the precise confusion this tool exists to
    prevent, sitting in its own recommended policy.
    """
    context = {
        "findings": [
            {
                "id": "1",
                "advisory": "CVE-2026-0001",
                "severity": "MEDIUM",
                "severity_rank": 3,
                "verdict": "affected",
                "kev": False,
                "age_days": 1,
                "epss": 0.0,
                "cvss": 0.0,
                "reach": {
                    "analysed": True,
                    "conclusive": status.is_conclusive,
                    "status": status.value,
                    "reachable": status.is_reachable,
                    "confidence": "low",
                    "confidence_rank": 1,
                    "reason": "",
                    "path_length": 0,
                    "via_dynamic_edges": False,
                },
            }
        ],
        "scan": {},
        "project": {},
        "counts": {},
    }
    policy = compile_policy(
        "findings.exists(f, f.reach.reachable || !f.reach.conclusive)", name="honest"
    )
    assert policy.evaluate_context(context).passed is not should_fail
