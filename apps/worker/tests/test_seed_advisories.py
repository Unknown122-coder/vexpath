"""Seeding the advisory corpus.

Needs a real Postgres: the write path uses ``ON CONFLICT`` and array columns,
and testing it against SQLite would prove nothing about the code that actually
runs. Start the stack with ``make up``, then ``make test-all``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import func, select

from vexpath_db.engine import create_sync_engine
from vexpath_db.tables import advisories, advisory_affected, advisory_snapshots, vulnerable_symbols
from vexpath_worker.jobs.seed_advisories import seed_snapshot

if TYPE_CHECKING:
    from sqlalchemy import Engine

pytestmark = pytest.mark.integration


@pytest.fixture
def engine(integration_database_url: str) -> Engine:
    # Short timeout: if Postgres is not running, skip quickly instead of
    # looking like a hung test suite.
    engine = create_sync_engine(integration_database_url, connect_timeout=3)
    try:
        with engine.connect() as connection:
            connection.execute(select(func.count()).select_from(advisories))
    except Exception as exc:  # noqa: BLE001 - a missing database skips, not fails
        engine.dispose()
        pytest.skip(f"integration database unavailable: {type(exc).__name__}: {exc}")
    yield engine
    engine.dispose()


def _count(engine: Engine, table: object) -> int:
    with engine.connect() as connection:
        result = connection.execute(select(func.count()).select_from(table))  # type: ignore[arg-type]
        return int(result.scalar_one())


def test_seeding_loads_the_snapshot(engine: Engine, snapshot_dir: Path) -> None:
    report = seed_snapshot(engine, snapshot_dir)

    assert report.snapshot_id == "test-snapshot-0001"
    assert report.advisories == 8
    assert _count(engine, advisories) >= 8
    assert _count(engine, advisory_affected) >= report.affected_packages
    assert _count(engine, vulnerable_symbols) >= report.symbols


def test_seeding_twice_changes_nothing(engine: Engine, snapshot_dir: Path) -> None:
    """Every job in this system gets retried, so idempotence is not optional."""
    first = seed_snapshot(engine, snapshot_dir)
    counts_after_first = (
        _count(engine, advisories),
        _count(engine, advisory_affected),
        _count(engine, vulnerable_symbols),
        _count(engine, advisory_snapshots),
    )

    second = seed_snapshot(engine, snapshot_dir)
    counts_after_second = (
        _count(engine, advisories),
        _count(engine, advisory_affected),
        _count(engine, vulnerable_symbols),
        _count(engine, advisory_snapshots),
    )

    assert first == second
    assert counts_after_first == counts_after_second


def test_the_snapshot_row_records_symbol_coverage(engine: Engine, snapshot_dir: Path) -> None:
    seed_snapshot(engine, snapshot_dir)
    with engine.connect() as connection:
        row = connection.execute(
            select(advisory_snapshots.c.counts, advisory_snapshots.c.ecosystems).where(
                advisory_snapshots.c.id == "test-snapshot-0001"
            )
        ).one()
    counts, ecosystems = row
    # Symbol coverage is the metric the product's usefulness rests on, so it is
    # stored with the snapshot rather than recomputed on demand.
    assert counts["PyPI"]["with_symbols"] == 5
    assert set(ecosystems) == {"PyPI", "npm"}


def test_affected_ranges_survive_the_round_trip(engine: Engine, snapshot_dir: Path) -> None:
    seed_snapshot(engine, snapshot_dir)
    with engine.connect() as connection:
        row = connection.execute(
            select(advisory_affected.c.ranges, advisory_affected.c.fixed_versions).where(
                advisory_affected.c.advisory_id == "CVE-2024-35195"
            )
        ).one()
    ranges, fixed_versions = row
    # OSV event shape is preserved rather than flattened, because flattening
    # loses advisories whose fix was reverted or backported.
    assert ranges[0]["type"] == "ECOSYSTEM"
    assert {event.get("fixed") for event in ranges[0]["events"]} == {None, "2.32.0"}
    assert fixed_versions == ["2.32.0"]


def test_the_load_is_batched_not_row_at_a_time(engine: Engine, snapshot_dir: Path) -> None:
    """The statement count must follow the batches, not the advisories.

    This started as a production failure rather than a preference. One
    statement per advisory is four round trips each -- upsert, two deletes,
    insert -- and PyPI has 19,575 advisories, so the first real load issued on
    the order of 78,000 statements and was still going when the host stopped
    the machine four and a half minutes in. The corpus is 48MB; none of that
    time was the data.

    Asserted by counting, because the symptom of losing it is slowness, and
    slowness in a loader nobody watches is invisible until it runs against a
    real corpus.
    """
    from sqlalchemy import event

    from vexpath_worker.jobs.seed_advisories import BATCH_SIZE

    executed: list[str] = []

    def record(
        conn: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        executed.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        report = seed_snapshot(engine, snapshot_dir)
    finally:
        event.remove(engine, "before_cursor_execute", record)

    batches = -(-report.advisories // BATCH_SIZE)
    # Per batch: one upsert, two deletes, and one insert for each child table.
    # Plus one for the snapshot row itself.
    assert len(executed) <= batches * 5 + 1, (
        f"{report.advisories} advisories took {len(executed)} statements in "
        f"{batches} batch(es); the loader has gone back to row-at-a-time"
    )
