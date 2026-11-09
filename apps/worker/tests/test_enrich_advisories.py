"""Refreshing exploitation signals over the stored corpus.

Needs a real Postgres, because the write path is an executemany against bound
parameters and the point is that it touches only four columns.

Marks its own rows, so running the suite does not destroy a corpus someone
loaded.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import delete, func, select

from vexpath_core.advisory.enrich import signals_from_mapping
from vexpath_core.ids import new_ulid
from vexpath_db.engine import create_sync_engine
from vexpath_db.tables import advisories, advisory_affected, vulnerable_symbols
from vexpath_worker.jobs.enrich_advisories import refresh_signals

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

MARKER = "ZZENRICH-"
SCORED = f"CVE-{MARKER}0001"
BY_ALIAS = f"GHSA-{MARKER}0002"
ALIAS_CVE = f"CVE-{MARKER}0002"
UNSCORED = f"CVE-{MARKER}0003"
NO_CVE = f"MAL-{MARKER}0004"


@pytest.fixture
def engine(integration_database_url: str) -> Iterator[Engine]:
    engine = create_sync_engine(integration_database_url, connect_timeout=3)
    try:
        with engine.connect() as connection:
            connection.execute(select(func.count()).select_from(advisories))
    except Exception as exc:  # noqa: BLE001 - a missing database skips, not fails
        engine.dispose()
        pytest.skip(f"integration database unavailable: {type(exc).__name__}: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture
def seeded(engine: Engine) -> Iterator[Engine]:
    _wipe(engine)
    _insert(engine)
    yield engine
    _wipe(engine)


def _wipe(engine: Engine) -> None:
    ours = select(advisories.c.id).where(advisories.c.id.like(f"%{MARKER}%"))
    with engine.begin() as connection:
        connection.execute(
            delete(vulnerable_symbols).where(vulnerable_symbols.c.advisory_id.in_(ours))
        )
        connection.execute(
            delete(advisory_affected).where(advisory_affected.c.advisory_id.in_(ours))
        )
        connection.execute(delete(advisories).where(advisories.c.id.like(f"%{MARKER}%")))


def _insert(engine: Engine) -> None:
    with engine.begin() as connection:
        for identifier, aliases in (
            (SCORED, []),
            (BY_ALIAS, [ALIAS_CVE]),
            (UNSCORED, []),
            (NO_CVE, []),
        ):
            connection.execute(
                advisories.insert().values(
                    id=identifier,
                    aliases=aliases,
                    summary="seeded for enrichment",
                    severity="HIGH",
                    cwe_ids=[],
                    references=[],
                    symbols_status="pending",
                )
            )
            connection.execute(
                advisory_affected.insert().values(
                    id=new_ulid(),
                    advisory_id=identifier,
                    ecosystem="PyPI",
                    package_name="widget",
                    purl_base="pkg:pypi/widget",
                    ranges=[],
                    versions=[],
                    fixed_versions=[],
                )
            )


def _signals():
    return signals_from_mapping(
        {SCORED: (0.75, 0.98), ALIAS_CVE: (0.10, 0.40)},
        {SCORED: date(2026, 2, 2)},
    )


def _row(engine: Engine, identifier: str) -> dict[str, object]:
    with engine.connect() as connection:
        return dict(
            connection.execute(
                select(
                    advisories.c.epss_score,
                    advisories.c.epss_percentile,
                    advisories.c.kev,
                    advisories.c.kev_added_at,
                    advisories.c.severity,
                    advisories.c.symbols_status,
                ).where(advisories.c.id == identifier)
            )
            .mappings()
            .one()
        )


def _run(engine: Engine):
    report = refresh_signals(engine, signals=_signals())
    return report


def test_scores_are_written_to_the_corpus(seeded: Engine) -> None:
    _run(seeded)
    row = _row(seeded, SCORED)
    assert row["epss_score"] == pytest.approx(0.75)
    assert row["epss_percentile"] == pytest.approx(0.98)
    assert row["kev"] is True
    assert row["kev_added_at"] == date(2026, 2, 2)


def test_an_advisory_is_matched_by_its_alias(seeded: Engine) -> None:
    """Both feeds are keyed by CVE, and much of OSV is GHSA-primary."""
    _run(seeded)
    row = _row(seeded, BY_ALIAS)
    assert row["epss_score"] == pytest.approx(0.10)


def test_an_unknown_advisory_is_left_unscored(seeded: Engine) -> None:
    """Zero would be a claim nobody made; absent is the truth."""
    _run(seeded)
    row = _row(seeded, UNSCORED)
    assert row["epss_score"] is None
    assert row["kev"] is False


def test_nothing_but_the_signal_columns_is_touched(seeded: Engine) -> None:
    """These signals change what to fix first, never what is reported."""
    before = _row(seeded, SCORED)
    _run(seeded)
    after = _row(seeded, SCORED)
    assert after["severity"] == before["severity"]
    assert after["symbols_status"] == before["symbols_status"]


def test_records_without_a_cve_are_counted_as_out_of_scope(seeded: Engine) -> None:
    """Found on the real corpus: 6,714 of 19,552 read as 34 per cent.

    12,003 of those records are malicious-package entries with no CVE, and both
    feeds are keyed by CVE, so they are out of scope rather than misses. The
    honest figure was 99 per cent.

    The ratio itself is asserted in ``test_the_coverage_denominator_excludes...``
    below, because this job reads the whole corpus and the local database holds
    whatever someone last loaded.
    """
    report = _run(seeded)
    assert report.scorable < report.advisories
    assert report.out_of_scope >= 1
    assert "with no CVE identifier" in report.summary_line()


def test_the_coverage_denominator_excludes_unscorable_records() -> None:
    """The arithmetic, with the real numbers that exposed it."""
    from vexpath_worker.jobs.enrich_advisories import EnrichJobReport

    honest = EnrichJobReport(
        advisories=19552,
        epss_updated=6714,
        kev_updated=21,
        kev_newly_listed=21,
        scorable=6766,
    )
    assert honest.epss_coverage == pytest.approx(0.992, abs=0.001)
    assert honest.out_of_scope == 12786

    # Dividing by the whole corpus is what made a working feed look broken.
    assert pytest.approx(0.343, abs=0.001) == 6714 / 19552


def test_coverage_falls_back_to_the_whole_corpus_when_unknown() -> None:
    """A report built without the count must not divide by zero."""
    from vexpath_worker.jobs.enrich_advisories import EnrichJobReport

    report = EnrichJobReport(advisories=10, epss_updated=5, kev_updated=0, kev_newly_listed=0)
    assert report.epss_coverage == pytest.approx(0.5)
    assert report.out_of_scope == 0

    empty = EnrichJobReport(advisories=0, epss_updated=0, kev_updated=0, kev_newly_listed=0)
    assert empty.epss_coverage == 0.0


def test_a_newly_listed_exploit_is_counted_once(seeded: Engine) -> None:
    """Moving from predicted to observed exploitation is worth a warning."""
    first = _run(seeded)
    assert first.kev_newly_listed >= 1
    # The second run changes nothing, so nothing is newly listed.
    second = _run(seeded)
    assert second.kev_newly_listed == 0


def test_no_signals_at_all_is_reported_rather_than_raised(seeded: Engine) -> None:
    """One third party's outage must not stop a security tool from updating."""
    from vexpath_core.advisory.enrich import ExploitSignals

    report = refresh_signals(seeded, signals=ExploitSignals(failures=("EPSS: down", "KEV: down")))
    assert report.advisories == 0
    assert len(report.failures) == 2
    # And the corpus is untouched.
    assert _row(seeded, SCORED)["epss_score"] is None


def test_a_rescore_overwrites_the_previous_value(seeded: Engine) -> None:
    _run(seeded)
    later = signals_from_mapping({SCORED: (0.01, 0.05)}, {})
    refresh_signals(seeded, signals=later)

    row = _row(seeded, SCORED)
    assert row["epss_score"] == pytest.approx(0.01)
    # And an advisory dropped from the catalogue stops being flagged, because
    # KEV membership is a statement about now.
    assert row["kev"] is False
    assert row["kev_added_at"] is None


def test_the_clock_is_not_consulted_for_a_known_date(seeded: Engine) -> None:
    _run(seeded)
    assert _row(seeded, SCORED)["kev_added_at"] != datetime.now(UTC).date()
