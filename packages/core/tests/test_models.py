"""Domain model invariants.

Most of these assert refusals. The models are the last place a wrong verdict
can be caught before it reaches a VEX document, so they refuse to represent
conclusions the analysis is not entitled to draw.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vexpath_core.enums import (
    Confidence,
    EdgeKind,
    ReachReason,
    ReachStatus,
    Severity,
    SymbolKind,
    SymbolSource,
    Verdict,
    VexJustification,
)
from vexpath_core.models.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    RangeEvent,
    RangeType,
)
from vexpath_core.models.finding import (
    AdvisoryRef,
    CallPathStep,
    ComponentRef,
    Finding,
    ReachabilityResult,
)

ADVISORY = AdvisoryRef(id="CVE-2024-35195", severity=Severity.HIGH)
COMPONENT = ComponentRef(
    purl="pkg:pypi/requests@2.31.0",
    ecosystem="PyPI",
    name="requests",
    version="2.31.0",
    direct=True,
)


def _unreachable(symbol: str = "requests.sessions.Session.send") -> ReachabilityResult:
    return ReachabilityResult(
        status=ReachStatus.UNREACHABLE,
        confidence=Confidence.HIGH,
        searched_symbols=(symbol,),
        explanation=f"{symbol} is not reachable from any detected entry point.",
    )


def _reachable(symbol: str = "requests.sessions.Session.send") -> ReachabilityResult:
    return ReachabilityResult(
        status=ReachStatus.REACHABLE_CONFIRMED,
        confidence=Confidence.HIGH,
        matched_symbols=(symbol,),
        searched_symbols=(symbol,),
        shortest_path=(
            CallPathStep(symbol="app.main.fetch", file="app/main.py", line=12),
            CallPathStep(symbol=symbol, file="requests/sessions.py", line=701),
        ),
        path_count=1,
    )


# --- The central invariant -------------------------------------------------


def test_uncertainty_cannot_clear_a_finding() -> None:
    """A finding must not be marked not_affected on the strength of a guess."""
    for status, reason in (
        (ReachStatus.SYMBOLS_UNKNOWN, ReachReason.NO_FIX_COMMIT),
        (ReachStatus.GRAPH_INCOMPLETE, ReachReason.PARSE_ERRORS),
    ):
        uncertain = ReachabilityResult(status=status, confidence=Confidence.LOW, reason=reason)
        with pytest.raises(ValidationError, match="only 'unreachable' may suppress"):
            Finding(
                id="01",
                advisory=ADVISORY,
                component=COMPONENT,
                verdict=Verdict.NOT_AFFECTED,
                justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                reach=uncertain,
            )


def test_a_reachable_finding_cannot_be_cleared() -> None:
    with pytest.raises(ValidationError, match="only 'unreachable' may suppress"):
        Finding(
            id="01",
            advisory=ADVISORY,
            component=COMPONENT,
            verdict=Verdict.NOT_AFFECTED,
            justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            reach=_reachable(),
        )


def test_proven_unreachability_clears_a_finding() -> None:
    finding = Finding(
        id="01",
        advisory=ADVISORY,
        component=COMPONENT,
        verdict=Verdict.NOT_AFFECTED,
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        reach=_unreachable(),
    )
    assert not finding.is_reachable
    assert not finding.needs_attention


def test_a_manual_suppression_is_the_one_documented_exception() -> None:
    # A human may accept a risk the analysis cannot clear, but the decision is
    # recorded against the finding rather than hidden in the verdict.
    finding = Finding(
        id="01",
        advisory=ADVISORY,
        component=COMPONENT,
        verdict=Verdict.NOT_AFFECTED,
        justification=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
        reach=_reachable(),
        suppressed_by="01SUPPRESSION",
    )
    assert finding.suppressed_by == "01SUPPRESSION"


def test_clearing_a_finding_requires_a_justification() -> None:
    with pytest.raises(ValidationError, match="requires an OpenVEX justification"):
        Finding(
            id="01",
            advisory=ADVISORY,
            component=COMPONENT,
            verdict=Verdict.NOT_AFFECTED,
            reach=_unreachable(),
        )


def test_a_justification_on_a_live_finding_is_rejected() -> None:
    with pytest.raises(ValidationError, match="applies only to a not_affected"):
        Finding(
            id="01",
            advisory=ADVISORY,
            component=COMPONENT,
            verdict=Verdict.AFFECTED,
            justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            reach=_reachable(),
        )


# --- Reachability result consistency ---------------------------------------


def test_a_reachable_result_must_name_what_it_reached() -> None:
    with pytest.raises(ValidationError, match="must name the symbols it reached"):
        ReachabilityResult(
            status=ReachStatus.REACHABLE_CONFIRMED,
            confidence=Confidence.HIGH,
        )


def test_an_unreachable_result_must_name_what_it_searched_for() -> None:
    # "Not affected" with no record of what was looked for is an unfalsifiable
    # claim, which is exactly what this product exists to avoid.
    with pytest.raises(ValidationError, match="must name the symbols it searched"):
        ReachabilityResult(status=ReachStatus.UNREACHABLE, confidence=Confidence.HIGH)


def test_an_uncertain_result_must_say_why() -> None:
    with pytest.raises(ValidationError, match="requires a reason"):
        ReachabilityResult(status=ReachStatus.SYMBOLS_UNKNOWN, confidence=Confidence.LOW)


def test_possible_means_a_dynamic_edge_was_involved() -> None:
    with pytest.raises(ValidationError, match="dynamic or opaque edge"):
        ReachabilityResult(
            status=ReachStatus.REACHABLE_POSSIBLE,
            confidence=Confidence.LOW,
            matched_symbols=("fixturelib.handlers.Handler.process",),
            via_dynamic_edges=False,
        )

    allowed = ReachabilityResult(
        status=ReachStatus.REACHABLE_POSSIBLE,
        confidence=Confidence.LOW,
        matched_symbols=("fixturelib.handlers.Handler.process",),
        shortest_path=(
            CallPathStep(symbol="app.dispatch.handle", edge_kind=EdgeKind.STATIC),
            CallPathStep(symbol="fixturelib.handlers.Handler.process", edge_kind=EdgeKind.DYNAMIC),
        ),
        via_dynamic_edges=True,
    )
    assert allowed.status.is_reachable
    assert not allowed.status.may_suppress


# --- Immutability and serialisation ---------------------------------------


def test_models_are_frozen() -> None:
    # Determinism depends on the pipeline building new objects rather than
    # mutating shared ones.
    finding = Finding(id="01", advisory=ADVISORY, component=COMPONENT, verdict=Verdict.AFFECTED)
    with pytest.raises(ValidationError):
        finding.verdict = Verdict.NOT_AFFECTED  # type: ignore[misc]


def test_unexpected_fields_are_rejected_at_the_boundary() -> None:
    with pytest.raises(ValidationError):
        ComponentRef(
            purl="pkg:pypi/requests@2.31.0",
            ecosystem="PyPI",
            name="requests",
            version="2.31.0",
            unexpected="value",  # type: ignore[call-arg]
        )


def test_findings_round_trip_through_json() -> None:
    original = Finding(
        id="01",
        advisory=ADVISORY,
        component=COMPONENT,
        verdict=Verdict.AFFECTED,
        fixed_in="2.32.0",
        reach=_reachable(),
    )
    assert Finding.model_validate_json(original.model_dump_json()) == original


# --- Advisory helpers ------------------------------------------------------


def test_osv_range_events_set_exactly_one_field() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        RangeEvent()
    with pytest.raises(ValidationError, match="exactly one"):
        RangeEvent(introduced="0", fixed="2.0.0")


def test_fixed_versions_are_collected_across_ranges() -> None:
    package = AffectedPackage(
        ecosystem="PyPI",
        name="requests",
        purl_base="pkg:pypi/requests",
        ranges=(
            AffectedRange(
                type=RangeType.ECOSYSTEM,
                events=(RangeEvent(introduced="0"), RangeEvent(fixed="2.31.0")),
            ),
            # A second branch, as happens with backported fixes.
            AffectedRange(
                type=RangeType.ECOSYSTEM,
                events=(RangeEvent(introduced="2.32.0"), RangeEvent(fixed="2.32.4")),
            ),
        ),
    )
    assert package.fixed_versions == ("2.31.0", "2.32.4")


def test_curated_symbols_override_extracted_ones() -> None:
    from vexpath_core.models.advisory import VulnerableSymbol

    def symbol(source: SymbolSource, name: str) -> VulnerableSymbol:
        return VulnerableSymbol(
            advisory_id="CVE-2024-35195",
            ecosystem="PyPI",
            package_name="requests",
            symbol=name,
            kind=SymbolKind.METHOD,
            source=source,
            confidence=Confidence.HIGH,
        )

    advisory = Advisory(
        id="CVE-2024-35195",
        symbols=(
            symbol(SymbolSource.FIX_COMMIT, "requests.sessions.Session.send"),
            symbol(SymbolSource.CURATED, "requests.sessions.Session.send"),
            symbol(SymbolSource.FIX_COMMIT, "requests.adapters.HTTPAdapter.send"),
        ),
    )
    resolved = advisory.symbols_for("PyPI", "requests")
    # A human reviewed the curated entry, so it wins and is not duplicated.
    assert len(resolved) == 2
    sends = [s for s in resolved if s.symbol == "requests.sessions.Session.send"]
    assert len(sends) == 1
    assert sends[0].source is SymbolSource.CURATED
