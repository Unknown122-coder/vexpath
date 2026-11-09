"""Measuring whether reachability analysis is possible.

The number this produces decides whether the call-graph engine is worth
building, so getting the denominator right matters as much as the arithmetic.
Measured against the real OSV corpus, leaving malicious-package records in the
denominator understated Python's fix-commit coverage as 33 % when the true
figure for analysable advisories is 89 %. These tests pin that distinction.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vexpath_core.advisory.coverage import FixReferenceTier, classify_fix_reference, measure
from vexpath_core.models.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    RangeEvent,
    RangeType,
)
from vexpath_core.models.common import Reference

NOW = datetime(2026, 11, 9, tzinfo=UTC)


def _advisory(
    advisory_id: str = "CVE-2024-0001",
    *,
    references: tuple[Reference, ...] = (),
    repo_url: str | None = None,
    fixed: str | None = "2.0.0",
    git_range: bool = False,
    withdrawn: bool = False,
    ecosystem: str = "PyPI",
    symbols: tuple[object, ...] = (),
) -> Advisory:
    ranges: list[AffectedRange] = []
    if git_range:
        ranges.append(
            AffectedRange(
                type=RangeType.GIT,
                repo="https://github.com/example/project",
                events=(RangeEvent(introduced="0"), RangeEvent(fixed="abc1234")),
            )
        )
    events = [RangeEvent(introduced="0")]
    if fixed is not None:
        events.append(RangeEvent(fixed=fixed))
    ranges.append(AffectedRange(type=RangeType.ECOSYSTEM, events=tuple(events)))

    return Advisory(
        id=advisory_id,
        references=references,
        repo_url=repo_url,
        withdrawn_at=NOW if withdrawn else None,
        symbols=symbols,  # type: ignore[arg-type]
        affected=(
            AffectedPackage(
                ecosystem=ecosystem,
                name="example",
                purl_base="pkg:pypi/example",
                ranges=tuple(ranges),
            ),
        ),
    )


# --- Tier classification ---------------------------------------------------


def test_a_commit_reference_is_the_best_tier() -> None:
    advisory = _advisory(
        references=(
            Reference(
                type="FIX", url="https://github.com/example/project/commit/2d8df8b9a1c4e5f6a7b8"
            ),
        )
    )
    assert classify_fix_reference(advisory) is FixReferenceTier.COMMIT


def test_a_git_range_with_a_fix_counts_as_a_commit_source() -> None:
    # A GIT range's fixed event is itself a commit identifier.
    assert classify_fix_reference(_advisory(git_range=True)) is FixReferenceTier.GIT_RANGE


def test_a_pull_request_is_a_weaker_tier() -> None:
    advisory = _advisory(
        references=(Reference(type="FIX", url="https://github.com/example/project/pull/42"),)
    )
    assert classify_fix_reference(advisory) is FixReferenceTier.PULL_REQUEST


def test_a_repository_and_a_fixed_version_allow_a_tag_diff() -> None:
    advisory = _advisory(repo_url="https://github.com/example/project", fixed="2.0.0")
    assert classify_fix_reference(advisory) is FixReferenceTier.TAG_DERIVABLE


def test_nothing_to_work_from_is_reported_as_such() -> None:
    advisory = _advisory(
        references=(Reference(type="ADVISORY", url="https://nvd.nist.gov/vuln/detail/CVE-x"),),
        repo_url=None,
        fixed=None,
    )
    assert classify_fix_reference(advisory) is FixReferenceTier.NONE


def test_the_best_available_tier_wins() -> None:
    # An advisory with both a commit reference and a derivable tag reports the
    # commit, because that is what extraction would actually use.
    advisory = _advisory(
        references=(
            Reference(
                type="FIX", url="https://github.com/example/project/commit/2d8df8b9a1c4e5f6a7b8"
            ),
        ),
        repo_url="https://github.com/example/project",
    )
    assert classify_fix_reference(advisory) is FixReferenceTier.COMMIT


def test_an_advisory_page_url_is_not_a_fix_reference() -> None:
    advisory = _advisory(
        references=(Reference(type="ADVISORY", url="https://github.com/advisories/GHSA-xxxx"),),
        repo_url=None,
        fixed=None,
    )
    assert classify_fix_reference(advisory) is FixReferenceTier.NONE


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/example/project/-/commit/2d8df8b9a1c4",
        "https://bitbucket.org/example/project/commits/2d8df8b9a1c4",
        "https://codeberg.org/example/project/commit/2d8df8b9a1c4",
    ],
)
def test_commit_urls_on_other_forges_are_recognised(url: str) -> None:
    assert (
        classify_fix_reference(_advisory(references=(Reference(type="FIX", url=url),)))
        is FixReferenceTier.COMMIT
    )


def test_only_usable_tiers_report_themselves_as_usable() -> None:
    for tier in FixReferenceTier:
        assert tier.is_usable == (tier is not FixReferenceTier.NONE)


# --- The denominator -------------------------------------------------------


def test_malicious_packages_are_excluded_from_the_denominator() -> None:
    """Measured against real data this changed Python's coverage from 33 % to 89 %.

    Malware has no fix commit because there is no fix, and reachability is the
    wrong question for it: installing it runs it. Counting those records against
    fix-commit coverage measures the wrong thing.
    """
    malicious = [
        _advisory(f"MAL-2026-{index:04d}", repo_url=None, fixed=None) for index in range(90)
    ]
    legitimate = [
        _advisory(
            f"CVE-2026-{index:04d}",
            references=(
                Reference(
                    type="FIX",
                    url="https://github.com/example/project/commit/2d8df8b9a1c4e5f6a7b8",
                ),
            ),
        )
        for index in range(10)
    ]

    report = measure([*malicious, *legitimate])
    pypi = report.for_ecosystem("PyPI")
    assert pypi is not None
    assert pypi.advisories == 10
    assert pypi.malicious == 90
    assert pypi.total_records == 100
    # Without the exclusion this would read 10 %.
    assert pypi.fix_reference_coverage == pytest.approx(1.0)
    assert report.malicious == 90


def test_a_malicious_record_is_identified_by_its_identifier() -> None:
    assert _advisory("MAL-2026-0001").is_malicious_package
    assert not _advisory("CVE-2026-0001").is_malicious_package
    # Aliases count too, because the primary identifier selection may prefer a
    # CVE that a malicious-package record also carries.
    aliased = _advisory("CVE-2026-0001").model_copy(update={"aliases": ("MAL-2026-0002",)})
    assert aliased.is_malicious_package


def test_withdrawn_records_are_excluded_too() -> None:
    report = measure(
        [
            _advisory("CVE-2026-0001", withdrawn=True),
            _advisory("CVE-2026-0002", git_range=True),
        ]
    )
    pypi = report.for_ecosystem("PyPI")
    assert pypi is not None
    assert pypi.advisories == 1
    assert pypi.withdrawn == 1
    assert report.withdrawn == 1


def test_an_empty_corpus_reports_zero_rather_than_dividing_by_it() -> None:
    report = measure([])
    assert report.advisories == 0
    assert report.ecosystems == ()


def test_exact_coverage_counts_only_precise_commits() -> None:
    report = measure(
        [
            _advisory("CVE-1", git_range=True),
            _advisory("CVE-2", repo_url="https://github.com/example/project"),
        ]
    )
    pypi = report.for_ecosystem("PyPI")
    assert pypi is not None
    # Both are usable, but only the first resolves to a commit rather than a
    # release diff that contains everything else shipped with it.
    assert pypi.fix_reference_coverage == pytest.approx(1.0)
    assert pypi.high_confidence_coverage == pytest.approx(0.5)


def test_symbol_coverage_and_fix_coverage_are_separate_numbers() -> None:
    # OSV publishes symbols for Go only. A zero here means nothing was handed
    # to us, not that nothing is possible.
    report = measure([_advisory("CVE-1", git_range=True)])
    pypi = report.for_ecosystem("PyPI")
    assert pypi is not None
    assert pypi.symbol_coverage == 0.0
    assert pypi.fix_reference_coverage == pytest.approx(1.0)


def test_the_committed_fixture_corpus_is_measurable(snapshot_dir: object) -> None:
    from pathlib import Path

    from vexpath_core.snapshot import read_snapshot

    assert isinstance(snapshot_dir, Path)
    metadata, advisories = read_snapshot(snapshot_dir)
    report = measure(advisories, snapshot_id=metadata.id)
    assert report.snapshot_id == "test-snapshot-0001"
    pypi = report.for_ecosystem("PyPI")
    assert pypi is not None
    assert pypi.advisories >= 1
