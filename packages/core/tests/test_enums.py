"""Closed vocabularies and the rules attached to them."""

from __future__ import annotations

import pytest

from vexpath_core.enums import (
    REACHABILITY_ECOSYSTEMS,
    VERDICT_TO_CYCLONEDX_STATE,
    Confidence,
    ReachStatus,
    Severity,
    Verdict,
    VexJustification,
    canonical_ecosystem,
    supports_reachability,
)


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("pypi", "PyPI"),
        ("PYPI", "PyPI"),
        ("NPM", "npm"),
        ("cargo", "crates.io"),
        ("crates.io", "crates.io"),
        ("conan", "ConanCenter"),
    ],
)
def test_ecosystem_names_canonicalise_to_osv_spelling(given: str, expected: str) -> None:
    assert canonical_ecosystem(given) == expected


def test_unknown_ecosystem_is_preserved() -> None:
    assert canonical_ecosystem("  BrandNewRegistry ") == "BrandNewRegistry"


def test_reachability_support_is_python_only() -> None:
    # ADR-0012. If this list ever grows, the per-ecosystem capability note in
    # the reports and the UI has to grow with it.
    assert frozenset({"PyPI"}) == REACHABILITY_ECOSYSTEMS
    assert supports_reachability("pypi")
    assert not supports_reachability("npm")


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (9.8, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (7.5, Severity.HIGH),
        (7.0, Severity.HIGH),
        (5.6, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.NONE),
    ],
)
def test_cvss_scores_map_to_the_standard_ratings(score: float, expected: Severity) -> None:
    assert Severity.from_cvss_score(score) == expected


def test_severity_ordering_places_unknown_between_none_and_low() -> None:
    # An unscored advisory deserves more attention than one scored harmless,
    # but must not outrank a real low finding.
    order = sorted(Severity, key=lambda severity: severity.rank)
    assert order == [
        Severity.NONE,
        Severity.UNKNOWN,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


def test_confidence_is_ordered() -> None:
    assert Confidence.LOW.rank < Confidence.MEDIUM.rank < Confidence.HIGH.rank


def test_only_proven_unreachability_may_clear_a_finding() -> None:
    # The product's central promise, expressed as code so it cannot be
    # weakened by accident. See docs/00-blueprint.md principle 3.
    assert ReachStatus.UNREACHABLE.may_suppress
    for status in ReachStatus:
        if status is not ReachStatus.UNREACHABLE:
            assert not status.may_suppress, status


def test_both_reachable_statuses_count_as_reachable() -> None:
    assert ReachStatus.REACHABLE_CONFIRMED.is_reachable
    assert ReachStatus.REACHABLE_POSSIBLE.is_reachable
    assert not ReachStatus.UNREACHABLE.is_reachable
    assert not ReachStatus.SYMBOLS_UNKNOWN.is_reachable


def test_every_verdict_maps_to_a_cyclonedx_state() -> None:
    assert set(VERDICT_TO_CYCLONEDX_STATE) == set(Verdict)


def test_openvex_justification_spellings_are_exact() -> None:
    # Fixed by the OpenVEX specification. A typo here produces a document that
    # validators reject, so the strings are asserted literally.
    assert VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value == (
        "vulnerable_code_not_in_execute_path"
    )
    assert VexJustification.COMPONENT_NOT_PRESENT.value == "component_not_present"
    assert VexJustification.VULNERABLE_CODE_NOT_PRESENT.value == "vulnerable_code_not_present"
    assert VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST.value == (
        "inline_mitigations_already_exist"
    )
    assert VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY.value == (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
