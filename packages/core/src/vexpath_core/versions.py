"""Version ordering and OSV affected-range evaluation.

Deciding whether an installed version falls inside an advisory's affected range
is the step where a scanner is most likely to be quietly wrong. Two rules
follow from that:

1. **Each ecosystem gets its own comparator.** PyPI orders versions by PEP 440,
   npm and friends by semver, and the two disagree about real version strings:
   PEP 440 reads ``1.0.0-rc1`` and ``1.0.0rc1`` as the same prerelease, semver
   accepts only the first spelling. Using one comparator everywhere produces
   wrong answers for whole ecosystems.

2. **Where there is no precise comparator, nothing is guessed.** Maven and
   NuGet have their own ordering rules that this module does not implement, so
   asking it to compare two Maven versions raises instead of returning a
   plausible-looking lie. Callers fall back to an advisory's explicit version
   list, and report the finding as needing investigation when that is empty.
   A missed finding that says "I could not tell" is recoverable; a silent
   wrong answer is not.

The range algorithm itself is the one the OSV specification defines: walk the
events of a range in version order, and let each ``introduced`` turn the
affected flag on while each ``fixed``, ``last_affected`` or ``limit`` turns it
off.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from functools import cmp_to_key
from typing import Final

import semver
from packaging.version import InvalidVersion
from packaging.version import Version as Pep440Version

from vexpath_core.enums import canonical_ecosystem
from vexpath_core.models.advisory import AffectedPackage, AffectedRange, RangeEvent, RangeType

#: Lowest possible version in any ecosystem, as OSV spells it.
ZERO: Final = "0"


class UnorderableVersionError(Exception):
    """Raised when two versions cannot be ordered with confidence.

    Either the ecosystem has no comparator here, or a version string does not
    parse under the one it has. Callers must treat this as "unknown", never as
    "not affected".
    """


# ---------------------------------------------------------------------------
# Per-ecosystem comparison
# ---------------------------------------------------------------------------

#: Ecosystems whose versions this module can order precisely.
PEP440_ECOSYSTEMS: Final = frozenset({"PyPI"})
SEMVER_ECOSYSTEMS: Final = frozenset(
    {"npm", "crates.io", "Go", "Hex", "Pub", "SwiftURL", "Hackage"}
)


def orders_versions(ecosystem: str) -> bool:
    """Return True if versions in this ecosystem can be ordered precisely."""
    canonical = canonical_ecosystem(ecosystem)
    return canonical in PEP440_ECOSYSTEMS or canonical in SEMVER_ECOSYSTEMS


def compare(ecosystem: str, left: str, right: str) -> int:
    """Return -1, 0 or 1 for ``left`` against ``right`` in ``ecosystem``.

    Raises:
        UnorderableVersionError: if the ecosystem has no comparator, or either
            string does not parse.
    """
    canonical = canonical_ecosystem(ecosystem)
    if canonical in PEP440_ECOSYSTEMS:
        return _compare_pep440(left, right)
    if canonical in SEMVER_ECOSYSTEMS:
        return _compare_semver(canonical, left, right)
    msg = (
        f"no version ordering implemented for ecosystem {canonical!r}; "
        "matching must fall back to the advisory's explicit version list"
    )
    raise UnorderableVersionError(msg)


def _compare_pep440(left: str, right: str) -> int:
    try:
        parsed_left = Pep440Version(left)
        parsed_right = Pep440Version(right)
    except InvalidVersion as exc:
        msg = f"not a PEP 440 version: {exc}"
        raise UnorderableVersionError(msg) from exc
    if parsed_left < parsed_right:
        return -1
    return 1 if parsed_left > parsed_right else 0


def _compare_semver(ecosystem: str, left: str, right: str) -> int:
    try:
        parsed_left = semver.Version.parse(_normalise_semver(ecosystem, left))
        parsed_right = semver.Version.parse(_normalise_semver(ecosystem, right))
    except (ValueError, TypeError) as exc:
        msg = f"not a semantic version: {exc}"
        raise UnorderableVersionError(msg) from exc
    return int(parsed_left.compare(parsed_right))


def _normalise_semver(ecosystem: str, version: str) -> str:
    """Coerce a version string into strict semver, where that is safe to do.

    Go module versions carry a ``v`` prefix, and several ecosystems publish
    two- or one-component versions that strict semver rejects. Both are
    mechanical, lossless fixes. Anything else is left alone so that it fails
    loudly rather than being reinterpreted.
    """
    cleaned = version.strip()
    if ecosystem == "Go" and cleaned.startswith("v"):
        cleaned = cleaned[1:]
    # Separate the core version from any prerelease or build metadata before
    # counting components, so "1.2-beta" is padded to "1.2.0-beta".
    core = cleaned
    suffix = ""
    for separator in ("-", "+"):
        index = core.find(separator)
        if index != -1:
            core, suffix = core[:index], core[index:] + suffix
            break
    parts = core.split(".")
    if len(parts) < 3 and all(part.isdigit() for part in parts if part):
        parts = [*parts, *(["0"] * (3 - len(parts)))]
        return ".".join(parts) + suffix
    return cleaned


def sort_versions(ecosystem: str, versions: Iterable[str]) -> list[str]:
    """Sort versions ascending.

    Raises:
        UnorderableVersionError: if any version cannot be ordered.
    """

    def compare_in_ecosystem(left: str, right: str) -> int:
        return compare(ecosystem, left, right)

    return sorted(versions, key=cmp_to_key(compare_in_ecosystem))


# ---------------------------------------------------------------------------
# OSV range evaluation
# ---------------------------------------------------------------------------


def version_in_range(ecosystem: str, version: str, affected_range: AffectedRange) -> bool:
    """Return True if ``version`` falls inside one OSV range.

    Implements the algorithm from the OSV specification: events are considered
    in version order, an ``introduced`` event turns the affected state on, and
    ``fixed``, ``last_affected`` or ``limit`` turn it off. A range that has
    been reopened by a later ``introduced``, which is how a reverted or
    backported fix is expressed, is therefore handled correctly.

    Raises:
        UnorderableVersionError: if the versions involved cannot be ordered.
    """
    if affected_range.type is RangeType.GIT:
        # Git ranges are commit-based. Deciding whether an installed release
        # contains a commit needs repository history, which the matcher does
        # not have; ecosystem ranges are what apply to a package version.
        msg = "GIT ranges cannot be evaluated against a package version"
        raise UnorderableVersionError(msg)

    affected = False
    for event in _sorted_events(ecosystem, affected_range.events):
        if event.introduced is not None:
            if event.introduced == ZERO or compare(ecosystem, version, event.introduced) >= 0:
                affected = True
        elif event.fixed is not None:
            if compare(ecosystem, version, event.fixed) >= 0:
                affected = False
        elif event.last_affected is not None:
            if compare(ecosystem, version, event.last_affected) > 0:
                affected = False
        elif event.limit is not None and compare(ecosystem, version, event.limit) >= 0:
            affected = False
    return affected


def _sorted_events(ecosystem: str, events: Sequence[RangeEvent]) -> list[RangeEvent]:
    """Order events by the version each one names.

    OSV requires producers to emit events in order, but real documents are not
    always well-formed, and an out-of-order ``fixed`` would silently clear an
    advisory. Sorting defensively costs nothing on a handful of events.
    """

    def version_of(event: RangeEvent) -> str:
        return event.introduced or event.fixed or event.last_affected or event.limit or ZERO

    def compare_events(left: RangeEvent, right: RangeEvent) -> int:
        left_version, right_version = version_of(left), version_of(right)
        if left_version == ZERO and right_version == ZERO:
            return 0
        if left_version == ZERO:
            return -1
        if right_version == ZERO:
            return 1
        result = compare(ecosystem, left_version, right_version)
        if result != 0:
            return result
        # At the same version, an introduced must be applied before a fixed,
        # otherwise a zero-width range would read as affected.
        return (left.introduced is None) - (right.introduced is None)

    return sorted(events, key=cmp_to_key(compare_events))


def affects_version(package: AffectedPackage, version: str) -> bool:
    """Return True if an advisory's affected package covers ``version``.

    The explicit version list is checked first, because it needs no ordering
    and is authoritative when present. Ranges are evaluated only if that does
    not settle it.

    Raises:
        UnorderableVersionError: if ranges must be consulted and the ecosystem's
            versions cannot be ordered.
    """
    if version in package.versions:
        return True

    ecosystem_ranges = [r for r in package.ranges if r.type is not RangeType.GIT]
    if not ecosystem_ranges:
        # Nothing orderable to consult. If an explicit list existed and did not
        # contain this version, the answer is a definite no.
        if package.versions:
            return False
        msg = f"{package.name} has neither explicit versions nor an ecosystem range"
        raise UnorderableVersionError(msg)

    return any(version_in_range(package.ecosystem, version, r) for r in ecosystem_ranges)


def nearest_fixed_version(package: AffectedPackage, version: str) -> str | None:
    """Return the lowest fixed version greater than ``version``.

    This is the upgrade a user should actually make: the smallest step that
    leaves the affected range. Returns None when no fixed version is known, or
    when the ecosystem's versions cannot be ordered.
    """
    candidates = package.fixed_versions
    if not candidates:
        return None
    try:
        ordered = sort_versions(package.ecosystem, candidates)
    except UnorderableVersionError:
        return None
    for candidate in ordered:
        try:
            if compare(package.ecosystem, candidate, version) > 0:
                return candidate
        except UnorderableVersionError:
            return None
    return None


__all__ = [
    "PEP440_ECOSYSTEMS",
    "SEMVER_ECOSYSTEMS",
    "ZERO",
    "UnorderableVersionError",
    "affects_version",
    "compare",
    "nearest_fixed_version",
    "orders_versions",
    "sort_versions",
    "version_in_range",
]
