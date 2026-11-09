"""CVSS base-score calculation.

Advisories publish a CVSS vector far more reliably than they publish a numeric
score, and the two sometimes disagree in upstream data. Computing the score
from the vector means severity is derived from the one field that is actually
authoritative, and means a disagreement can be detected rather than inherited.

Implements the CVSS version 3.0 and 3.1 base-score specifications. The two
differ only in how the final value is rounded, and both branches are here.

Version 4.0 is deliberately not scored. Its base score is defined by a lookup
table of several hundred entries rather than a closed formula, so a hand-rolled
approximation would be wrong in ways nobody would notice. A 4.0 vector is
parsed and carried, and its qualitative severity is taken from the advisory
when the source provides one.
"""

from __future__ import annotations

import math
from typing import Final

from vexpath_core.enums import Severity

#: Attack Vector.
_AV: Final[dict[str, float]] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
#: Attack Complexity.
_AC: Final[dict[str, float]] = {"L": 0.77, "H": 0.44}
#: Privileges Required, which depends on whether Scope changed.
_PR_UNCHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.68, "H": 0.50}
#: User Interaction.
_UI: Final[dict[str, float]] = {"N": 0.85, "R": 0.62}
#: Confidentiality, Integrity and Availability impact. CVSS 3.x spells the
#: middle value "L" for Low; "M" belongs to CVSS 2.0 and must not appear here.
_CIA: Final[dict[str, float]] = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED_METRICS: Final = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class InvalidCvssVectorError(Exception):
    """Raised when a vector string cannot be scored.

    Carrying an unparsable vector is fine; inventing a score for it is not.
    """


def parse_vector(vector: str) -> tuple[str, dict[str, str]]:
    """Split a CVSS vector into its version and metrics.

    Returns:
        The version string, such as ``"3.1"``, and the metric abbreviations
        mapped to their values.

    Raises:
        InvalidCvssVectorError: if the string is not a CVSS vector.
    """
    cleaned = vector.strip()
    parts = [part for part in cleaned.split("/") if part]
    if not parts or not parts[0].upper().startswith("CVSS:"):
        msg = f"not a CVSS vector: {vector!r}"
        raise InvalidCvssVectorError(msg)

    version = parts[0].split(":", 1)[1]
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, separator, value = part.partition(":")
        if not separator:
            msg = f"malformed metric {part!r} in vector {vector!r}"
            raise InvalidCvssVectorError(msg)
        metrics[key.upper()] = value.upper()
    return version, metrics


def base_score(vector: str) -> float:
    """Return the CVSS base score for a version 3.0 or 3.1 vector.

    Raises:
        InvalidCvssVectorError: if the vector is not version 3.x, or is missing a
            base metric, or carries a value the specification does not define.
    """
    version, metrics = parse_vector(vector)
    if not version.startswith("3."):
        msg = (
            f"CVSS {version} base scores are not computed here; only 3.0 and 3.1 "
            "have a closed-form formula"
        )
        raise InvalidCvssVectorError(msg)

    missing = [metric for metric in _REQUIRED_METRICS if metric not in metrics]
    if missing:
        msg = f"vector is missing base metric(s) {', '.join(missing)}: {vector!r}"
        raise InvalidCvssVectorError(msg)

    scope_changed = metrics["S"] == "C"
    try:
        attack_vector = _AV[metrics["AV"]]
        attack_complexity = _AC[metrics["AC"]]
        privileges = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        interaction = _UI[metrics["UI"]]
        confidentiality = _CIA[metrics["C"]]
        integrity = _CIA[metrics["I"]]
        availability = _CIA[metrics["A"]]
    except KeyError as exc:
        msg = f"undefined metric value {exc.args[0]!r} in vector {vector!r}"
        raise InvalidCvssVectorError(msg) from exc

    impact_subscore = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if scope_changed:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
    else:
        impact = 6.42 * impact_subscore

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * attack_vector * attack_complexity * privileges * interaction
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08

    capped = min(combined, 10.0)
    return _roundup_3_1(capped) if version == "3.1" else _round_3_0(capped)


def _roundup_3_1(value: float) -> float:
    """Round up to one decimal place, as CVSS 3.1 defines it.

    The specification defines this with integer arithmetic precisely because
    floating-point rounding gave different answers across implementations.
    """
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (math.floor(scaled / 10_000) + 1) / 10


def _round_3_0(value: float) -> float:
    """Round to one decimal place, as CVSS 3.0 did."""
    return math.floor(value * 10 + 0.5) / 10


def severity_from_vector(vector: str) -> Severity:
    """Return the qualitative rating for a vector.

    Raises:
        InvalidCvssVectorError: if the vector cannot be scored.
    """
    return Severity.from_cvss_score(base_score(vector))


def try_base_score(vector: str) -> float | None:
    """Return the base score, or None if the vector cannot be scored.

    For callers normalising third-party data, where an unscorable vector is a
    fact to record rather than an error to raise.
    """
    try:
        return base_score(vector)
    except InvalidCvssVectorError:
        return None


def vector_version(vector: str) -> str | None:
    """Return a vector's version, or None if it is not a CVSS vector."""
    try:
        return parse_vector(vector)[0]
    except InvalidCvssVectorError:
        return None


__all__ = [
    "InvalidCvssVectorError",
    "base_score",
    "parse_vector",
    "severity_from_vector",
    "try_base_score",
    "vector_version",
]
