"""Writing the database's corpus back out as a snapshot.

This is the step that gets extracted symbols to the command-line tool, which
reads snapshot directories and never touches the database. If a symbol does not
survive this round trip it may as well not have been extracted.

Needs a real Postgres, and marks its own rows so running the suite does not
destroy a corpus someone loaded.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import delete, func, select

from vexpath_core.enums import Confidence, SymbolKind, SymbolSource, SymbolsStatus
from vexpath_core.ids import new_ulid
from vexpath_core.snapshot import read_snapshot
from vexpath_db.engine import create_sync_engine
from vexpath_db.tables import advisories, advisory_affected, vulnerable_symbols
from vexpath_worker.jobs.export_snapshot import export_snapshot

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

#: Marks rows this suite owns. The local database is shared with development.
MARKER = "ZZEXPORT-"


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


WITH_SYMBOLS = f"CVE-{MARKER}0001"
WITHOUT_SYMBOLS = f"CVE-{MARKER}0002"
ECOSYSTEM = "ZZTestEco"


def _insert(engine: Engine) -> None:
    """Two advisories in a private ecosystem: one with symbols, one without."""
    with engine.begin() as connection:
        for identifier, summary in (
            (WITH_SYMBOLS, "a fix whose symbols were extracted"),
            (WITHOUT_SYMBOLS, "a fix nobody has diffed yet"),
        ):
            connection.execute(
                advisories.insert().values(
                    id=identifier,
                    aliases=[f"GHSA-{identifier}"],
                    summary=summary,
                    details="Details that must survive the round trip.",
                    severity="HIGH",
                    cwe_ids=["CWE-22"],
                    references=[
                        {"type": "FIX", "url": "https://github.com/a/b/commit/" + "c" * 40}
                    ],
                    repo_url="https://github.com/a/b",
                    kev=True,
                    epss_score=0.42,
                    modified_at=datetime(2026, 11, 1, tzinfo=UTC),
                    symbols_status=(
                        SymbolsStatus.EXTRACTED.value
                        if identifier == WITH_SYMBOLS
                        else SymbolsStatus.PENDING.value
                    ),
                )
            )
            connection.execute(
                advisory_affected.insert().values(
                    id=new_ulid(),
                    advisory_id=identifier,
                    ecosystem=ECOSYSTEM,
                    package_name="widget",
                    purl_base="pkg:pypi/widget",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                        }
                    ],
                    versions=["1.0.0", "1.5.0"],
                    fixed_versions=["2.0.0"],
                )
            )

        connection.execute(
            vulnerable_symbols.insert().values(
                id=new_ulid(),
                advisory_id=WITH_SYMBOLS,
                ecosystem=ECOSYSTEM,
                package_name="widget",
                symbol="widget.core.Thing.run",
                kind=SymbolKind.METHOD.value,
                source=SymbolSource.FIX_COMMIT.value,
                confidence=Confidence.HIGH.value,
                file_path="widget/core.py",
                fix_commit="c" * 40,
            )
        )


def _exported(engine: Engine, directory: Path, **kwargs: object):
    return export_snapshot(engine, directory, ecosystems=[ECOSYSTEM], **kwargs)  # type: ignore[arg-type]


def test_an_extracted_symbol_survives_the_round_trip(seeded: Engine, tmp_path: Path) -> None:
    """The whole reason this job exists."""
    report = _exported(seeded, tmp_path / "out")
    assert report.advisories == 2
    assert report.symbols == 1
    assert report.with_symbols == 1

    _, records = read_snapshot(tmp_path / "out")
    found = next(record for record in records if record.id == WITH_SYMBOLS)
    symbol = found.symbols[0]
    assert symbol.symbol == "widget.core.Thing.run"
    assert symbol.source is SymbolSource.FIX_COMMIT
    assert symbol.confidence is Confidence.HIGH
    assert symbol.fix_commit == "c" * 40
    assert symbol.file_path == "widget/core.py"


def test_the_written_snapshot_verifies_like_a_downloaded_one(
    seeded: Engine, tmp_path: Path
) -> None:
    """Everything that reads a snapshot must read this one unchanged."""
    report = _exported(seeded, tmp_path / "out")
    metadata, _ = read_snapshot(tmp_path / "out")
    assert metadata.content_sha256 == report.content_sha256
    assert metadata.core_version is not None


def test_every_field_a_verdict_depends_on_survives(seeded: Engine, tmp_path: Path) -> None:
    _exported(seeded, tmp_path / "out")
    _, records = read_snapshot(tmp_path / "out")
    found = next(record for record in records if record.id == WITH_SYMBOLS)

    assert found.aliases == (f"GHSA-{WITH_SYMBOLS}",)
    assert found.repo_url == "https://github.com/a/b"
    assert found.kev is True
    assert found.epss_score == pytest.approx(0.42)
    assert found.references[0].url.endswith("c" * 40)

    package = found.affected[0]
    assert package.name == "widget"
    assert package.versions == ("1.0.0", "1.5.0")
    assert package.fixed_versions == ("2.0.0",)


def test_advisories_without_symbols_are_still_written(seeded: Engine, tmp_path: Path) -> None:
    """An advisory missing from a snapshot produces no finding at all.

    That is worse than one left under investigation, so the default export is
    the whole corpus rather than only the enriched part.
    """
    _exported(seeded, tmp_path / "out")
    _, records = read_snapshot(tmp_path / "out")
    assert {record.id for record in records} == {WITH_SYMBOLS, WITHOUT_SYMBOLS}


def test_a_symbols_only_export_can_be_asked_for(seeded: Engine, tmp_path: Path) -> None:
    report = _exported(seeded, tmp_path / "out", only_with_symbols=True)
    assert report.advisories == 1
    _, records = read_snapshot(tmp_path / "out")
    assert [record.id for record in records] == [WITH_SYMBOLS]


def test_an_unrelated_ecosystem_is_excluded(seeded: Engine, tmp_path: Path) -> None:
    report = export_snapshot(seeded, tmp_path / "out", ecosystems=["NoSuchEcosystem"])
    assert report.advisories == 0
    assert report.symbol_coverage == 0.0
    # Still a readable snapshot, not a half-written directory.
    metadata, records = read_snapshot(tmp_path / "out")
    assert records == ()
    assert metadata.content_sha256


def test_the_summary_states_coverage(seeded: Engine, tmp_path: Path) -> None:
    report = _exported(seeded, tmp_path / "out")
    summary = report.summary_line()
    assert "2 advisories" in summary
    assert "50.0% symbol coverage" in summary
