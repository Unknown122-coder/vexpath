"""CVSS base-score calculation.

The expected values are the published scores for well-known vectors. Severity
drives what a policy blocks, so an arithmetic slip here changes which builds
fail.
"""

from __future__ import annotations

import pytest

from sscp_core.cvss import (
    InvalidCvssVectorError,
    base_score,
    parse_vector,
    severity_from_vector,
    try_base_score,
    vector_version,
)
from sscp_core.enums import Severity


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        # Unauthenticated remote code execution: the canonical 9.8.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # Remote information disclosure.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        # Remote denial of service.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        # Local privilege escalation.
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        # Reflected cross-site scripting, where scope changes.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        # High complexity, user interaction required.
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3),
        # Scope change with high privileges required.
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.2),
        # Physical access, minimal impact.
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        # No impact at all scores zero, not a floor value.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_known_vectors_score_correctly(vector: str, expected: float) -> None:
    assert base_score(vector) == pytest.approx(expected)


def test_version_3_0_is_also_scored() -> None:
    # 3.0 and 3.1 differ only in rounding, and both appear in real advisory data.
    assert base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == pytest.approx(9.8)


def test_severity_follows_the_standard_thresholds() -> None:
    assert severity_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is (
        Severity.CRITICAL
    )
    assert severity_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") is Severity.HIGH
    assert severity_from_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N") is (Severity.MEDIUM)
    assert severity_from_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") is Severity.LOW
    assert severity_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") is Severity.NONE


def test_the_impact_metrics_use_the_version_3_spelling() -> None:
    """CVSS 3.x impact is H, L or N. Accepting M would be a 2.0 leftover."""
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L") > 0
    with pytest.raises(InvalidCvssVectorError, match=r"undefined metric value 'M'"):
        base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:M/A:M")


def test_privileges_required_depends_on_scope() -> None:
    # PR:L is weighted higher when scope changes, so the two must differ.
    unchanged = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    changed = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert changed > unchanged


def test_version_4_is_not_scored() -> None:
    # The 4.0 base score comes from a large lookup table rather than a formula,
    # so approximating it would be wrong in ways nobody would notice.
    with pytest.raises(InvalidCvssVectorError, match=r"only 3\.0 and 3\.1"):
        base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


def test_a_truncated_vector_is_rejected() -> None:
    with pytest.raises(InvalidCvssVectorError, match="missing base metric"):
        base_score("CVSS:3.1/AV:N/AC:L")


def test_a_non_vector_is_rejected() -> None:
    with pytest.raises(InvalidCvssVectorError, match="not a CVSS vector"):
        base_score("9.8")


def test_parse_vector_returns_version_and_metrics() -> None:
    version, metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert version == "3.1"
    assert metrics["AV"] == "N"
    assert metrics["S"] == "U"


def test_the_tolerant_helpers_report_absence_rather_than_raising() -> None:
    # Used when normalising third-party data, where an unscorable vector is a
    # fact to record rather than an error to abort on.
    assert try_base_score("not a vector") is None
    assert vector_version("not a vector") is None
    assert vector_version("CVSS:4.0/AV:N") == "4.0"
