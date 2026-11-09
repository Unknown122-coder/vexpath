"""Version ordering and OSV range evaluation.

The matcher is where a scanner is most likely to be quietly wrong, so these
tests lean on the awkward cases: prereleases, epochs, reopened ranges, and
ecosystems whose ordering is deliberately not implemented.
"""

from __future__ import annotations

import pytest

from sscp_core.models.advisory import AffectedPackage, AffectedRange, RangeEvent, RangeType
from sscp_core.versions import (
    UnorderableVersionError,
    affects_version,
    compare,
    nearest_fixed_version,
    orders_versions,
    sort_versions,
    version_in_range,
)


def _ecosystem_range(*events: RangeEvent) -> AffectedRange:
    return AffectedRange(type=RangeType.ECOSYSTEM, events=events)


def _package(
    ecosystem: str = "PyPI",
    name: str = "requests",
    ranges: tuple[AffectedRange, ...] = (),
    versions: tuple[str, ...] = (),
) -> AffectedPackage:
    return AffectedPackage(
        ecosystem=ecosystem,
        name=name,
        purl_base=f"pkg:pypi/{name}",
        ranges=ranges,
        versions=versions,
    )


# --- Ordering --------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.0.0", "2.0.0", -1),
        ("2.0.0", "1.0.0", 1),
        ("1.0.0", "1.0.0", 0),
        # PEP 440: a prerelease sorts below its release.
        ("1.0.0rc1", "1.0.0", -1),
        # And the two spellings of a prerelease are the same version.
        ("1.0.0-rc1", "1.0.0rc1", 0),
        # Post-releases sort above.
        ("1.0.0", "1.0.0.post1", -1),
        # An epoch outranks everything else.
        ("1!1.0", "999.0", 1),
        # Zero padding is not significant.
        ("1.01", "1.1", 0),
    ],
)
def test_pypi_versions_order_by_pep_440(left: str, right: str, expected: int) -> None:
    assert compare("PyPI", left, right) == expected


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.0.0", "1.0.1", -1),
        ("1.0.0-beta", "1.0.0", -1),
        ("1.0.0-alpha", "1.0.0-beta", -1),
        # Build metadata does not affect precedence.
        ("1.0.0+build1", "1.0.0+build2", 0),
    ],
)
def test_npm_versions_order_by_semver(left: str, right: str, expected: int) -> None:
    assert compare("npm", left, right) == expected


def test_go_versions_lose_their_v_prefix() -> None:
    # Go module versions are published as v1.9.1; stripping the prefix is
    # mechanical and lossless.
    assert compare("Go", "v1.9.1", "v1.10.0") == -1
    assert compare("Go", "v1.9.1", "1.9.1") == 0


def test_short_semver_versions_are_padded() -> None:
    # Several registries publish two-component versions that strict semver
    # rejects. Padding is safe; reinterpreting anything else is not.
    assert compare("npm", "1.2", "1.2.0") == 0
    assert compare("npm", "1.2-beta", "1.2.0-beta") == 0


def test_ecosystems_without_a_comparator_refuse_to_guess() -> None:
    """A plausible-looking wrong answer is worse than an admitted unknown."""
    assert not orders_versions("Maven")
    with pytest.raises(UnorderableVersionError, match="no version ordering implemented"):
        compare("Maven", "1.0.0", "1.0.1")


def test_an_unparsable_version_is_not_silently_ordered() -> None:
    with pytest.raises(UnorderableVersionError, match="not a PEP 440 version"):
        compare("PyPI", "not-a-version", "1.0.0")
    with pytest.raises(UnorderableVersionError, match="not a semantic version"):
        compare("npm", "not-a-version", "1.0.0")


def test_sorting_uses_the_ecosystem_comparator() -> None:
    assert sort_versions("PyPI", ["2.0", "1.0rc1", "1.0", "10.0"]) == [
        "1.0rc1",
        "1.0",
        "2.0",
        "10.0",
    ]


# --- Range evaluation ------------------------------------------------------


def test_an_open_range_affects_everything_from_its_introduction() -> None:
    affected_range = _ecosystem_range(RangeEvent(introduced="0"))
    assert version_in_range("PyPI", "0.1", affected_range)
    assert version_in_range("PyPI", "99.0", affected_range)


def test_a_fixed_event_closes_the_range() -> None:
    affected_range = _ecosystem_range(RangeEvent(introduced="0"), RangeEvent(fixed="2.32.0"))
    assert version_in_range("PyPI", "2.31.0", affected_range)
    # The fixed version itself is not affected.
    assert not version_in_range("PyPI", "2.32.0", affected_range)
    assert not version_in_range("PyPI", "2.33.0", affected_range)


def test_versions_below_the_introduction_are_unaffected() -> None:
    affected_range = _ecosystem_range(RangeEvent(introduced="2.0.0"), RangeEvent(fixed="2.5.0"))
    assert not version_in_range("PyPI", "1.9.0", affected_range)
    assert version_in_range("PyPI", "2.0.0", affected_range)
    assert not version_in_range("PyPI", "2.5.0", affected_range)


def test_last_affected_includes_the_version_it_names() -> None:
    # Unlike fixed, last_affected is inclusive. Getting this backwards would
    # clear a genuinely vulnerable release.
    affected_range = _ecosystem_range(
        RangeEvent(introduced="1.0.0"), RangeEvent(last_affected="1.4.0")
    )
    assert version_in_range("PyPI", "1.4.0", affected_range)
    assert not version_in_range("PyPI", "1.4.1", affected_range)


def test_a_reopened_range_is_affected_again() -> None:
    """A reverted or backported fix reopens the range, and must still match."""
    affected_range = _ecosystem_range(
        RangeEvent(introduced="0"),
        RangeEvent(fixed="2.31.0"),
        RangeEvent(introduced="2.32.0"),
        RangeEvent(fixed="2.32.4"),
    )
    assert version_in_range("PyPI", "2.30.0", affected_range)
    assert not version_in_range("PyPI", "2.31.0", affected_range)
    assert not version_in_range("PyPI", "2.31.9", affected_range)
    assert version_in_range("PyPI", "2.32.0", affected_range)
    assert version_in_range("PyPI", "2.32.3", affected_range)
    assert not version_in_range("PyPI", "2.32.4", affected_range)


def test_events_out_of_order_are_sorted_before_evaluation() -> None:
    # Real documents are not always well-formed, and an out-of-order fixed
    # event would otherwise clear the advisory for every version.
    affected_range = _ecosystem_range(RangeEvent(fixed="2.32.0"), RangeEvent(introduced="0"))
    assert version_in_range("PyPI", "2.31.0", affected_range)
    assert not version_in_range("PyPI", "2.32.0", affected_range)


def test_git_ranges_are_not_evaluated_against_a_package_version() -> None:
    # Deciding whether a release contains a commit needs repository history,
    # which the matcher does not have.
    git_range = AffectedRange(
        type=RangeType.GIT,
        repo="https://github.com/psf/requests",
        events=(RangeEvent(introduced="0"),),
    )
    with pytest.raises(UnorderableVersionError, match="GIT ranges"):
        version_in_range("PyPI", "2.31.0", git_range)


# --- Package-level matching ------------------------------------------------


def test_an_explicit_version_list_is_authoritative() -> None:
    package = _package(versions=("2.31.0", "2.30.0"))
    assert affects_version(package, "2.31.0")
    assert not affects_version(package, "2.32.0")


def test_ranges_are_consulted_when_the_list_does_not_settle_it() -> None:
    package = _package(
        ranges=(_ecosystem_range(RangeEvent(introduced="0"), RangeEvent(fixed="2.32.0")),),
        versions=("2.30.0",),
    )
    assert affects_version(package, "2.30.0")
    assert affects_version(package, "2.31.0")
    assert not affects_version(package, "2.32.0")


def test_git_only_advisories_fall_back_to_the_explicit_list() -> None:
    git_range = AffectedRange(
        type=RangeType.GIT,
        repo="https://github.com/psf/requests",
        events=(RangeEvent(introduced="0"),),
    )
    package = _package(ranges=(git_range,), versions=("2.31.0",))
    assert affects_version(package, "2.31.0")
    assert not affects_version(package, "2.32.0")


def test_an_advisory_with_nothing_usable_is_an_admitted_unknown() -> None:
    git_range = AffectedRange(
        type=RangeType.GIT,
        repo="https://github.com/psf/requests",
        events=(RangeEvent(introduced="0"),),
    )
    with pytest.raises(UnorderableVersionError, match="neither explicit versions"):
        affects_version(_package(ranges=(git_range,)), "2.31.0")


def test_unorderable_ecosystems_still_match_an_explicit_list() -> None:
    package = _package(ecosystem="Maven", name="jackson-databind", versions=("2.9.10",))
    assert affects_version(package, "2.9.10")
    assert not affects_version(package, "2.9.11")

    with_range = _package(
        ecosystem="Maven",
        name="jackson-databind",
        ranges=(_ecosystem_range(RangeEvent(introduced="0"), RangeEvent(fixed="2.10.0")),),
    )
    with pytest.raises(UnorderableVersionError):
        affects_version(with_range, "2.9.10")


# --- Upgrade advice --------------------------------------------------------


def test_the_nearest_fix_is_the_smallest_upgrade_that_escapes() -> None:
    package = _package(
        ranges=(
            _ecosystem_range(RangeEvent(introduced="0"), RangeEvent(fixed="1.26.18")),
            _ecosystem_range(RangeEvent(introduced="2.0.0"), RangeEvent(fixed="2.0.7")),
        )
    )
    # From a 1.x release, the 1.x fix is the right advice, not the 2.x one.
    assert nearest_fixed_version(package, "1.26.17") == "1.26.18"
    assert nearest_fixed_version(package, "2.0.6") == "2.0.7"


def test_no_fix_means_no_advice() -> None:
    package = _package(ranges=(_ecosystem_range(RangeEvent(introduced="0")),))
    assert nearest_fixed_version(package, "1.0.0") is None


def test_no_advice_is_offered_for_an_unorderable_ecosystem() -> None:
    package = _package(
        ecosystem="Maven",
        ranges=(_ecosystem_range(RangeEvent(introduced="0"), RangeEvent(fixed="2.10.0")),),
    )
    assert nearest_fixed_version(package, "2.9.10") is None
