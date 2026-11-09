"""Extracting vulnerable symbols from fix commits, into the database.

Needs a real Postgres. The write path uses ``ON CONFLICT`` on a composite
unique constraint, a partial index as its work queue, and a per-advisory
transaction, and none of that is exercised by SQLite. Start the stack with
``make up``, then ``make test-all``.

Commits come from recorded diffs, so these run offline and identically every
time. What is being tested is the job: which advisories it picks, in what
order, what it writes, how many times it retries, and whether it is safe to
kill halfway.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import delete, func, select, update

from vexpath_core.enums import Confidence, SymbolsStatus
from vexpath_core.ids import new_ulid
from vexpath_core.models.advisory import Reference
from vexpath_core.patchdiff.fetch import CommitDiff, FetchError, RecordedCommitSource
from vexpath_core.patchdiff.unidiff import FileDiff
from vexpath_db.engine import create_sync_engine
from vexpath_db.tables import advisories, advisory_affected, vulnerable_symbols
from vexpath_worker.jobs.extract_symbols import (
    MAX_ATTEMPTS,
    extraction_backlog,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

SHA = "a" * 40
OTHER_SHA = "b" * 40
REPOSITORY = "https://github.com/psf/requests"

POST_SOURCE = """\
import os


class Session:
    def send(self, request, **kwargs):
        verify = kwargs.get("verify", True)
        return self.adapter.send(request, verify=verify)
"""

PRE_SOURCE = """\
import os


class Session:
    def send(self, request, **kwargs):
        return self.adapter.send(request)
"""


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


#: Identifier prefix every advisory these tests create. The local database is
#: shared with development, and a suite that deletes everything destroys a
#: loaded corpus someone spent minutes on. Only rows carrying this marker are
#: removed, and the queries filter on it so counts mean what they say even
#: with 20,000 real advisories alongside.
MARKER = "ZZTEST-"


@pytest.fixture
def clean(engine: Engine) -> Iterator[Engine]:
    """Remove this suite's own rows, before and after, and nothing else."""
    _CREATED.clear()
    _wipe(engine)
    yield engine
    _wipe(engine)
    _CREATED.clear()


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


#: Advisories the current test created, in insertion order. Passed to the job
#: so its queue is this test's rows rather than whatever corpus the local
#: database happens to hold.
_CREATED: list[str] = []


def _run(engine: Engine, **kwargs: object):
    """Run extraction over only the advisories this test created."""
    from vexpath_worker.jobs.extract_symbols import extract_symbols as _extract

    return _extract(engine, advisory_ids=tuple(_CREATED), **kwargs)  # type: ignore[arg-type]


def _insert(
    engine: Engine,
    advisory_id: str,
    *,
    package: str = "requests",
    repository: str | None = REPOSITORY,
    commit: str | None = SHA,
    status: SymbolsStatus = SymbolsStatus.PENDING,
    attempts: int = 0,
    withdrawn: bool = False,
    ecosystem: str = "PyPI",
) -> None:
    """Put one advisory in the corpus, shaped the way sync would leave it."""
    _CREATED.append(advisory_id)
    references = (
        [Reference(type="FIX", url=f"{repository}/commit/{commit}").model_dump(mode="json")]
        if repository and commit
        else []
    )

    with engine.begin() as connection:
        connection.execute(
            advisories.insert().values(
                id=advisory_id,
                aliases=[],
                summary=f"{package} needs a fix",
                details="",
                severity="MEDIUM",
                cwe_ids=[],
                references=references,
                repo_url=repository,
                symbols_status=status.value,
                symbols_attempts=attempts,
                withdrawn_at=datetime(2026, 1, 1, tzinfo=UTC) if withdrawn else None,
            )
        )
        connection.execute(
            advisory_affected.insert().values(
                id=new_ulid(),
                advisory_id=advisory_id,
                ecosystem=ecosystem,
                package_name=package,
                purl_base=f"pkg:pypi/{package}",
                ranges=[],
                versions=[],
                fixed_versions=["2.32.0"],
            )
        )


def _file_diff(path: str, added: list[int], removed: list[int]) -> FileDiff:
    return FileDiff(old_path=path, new_path=path, added_lines=added, removed_lines=removed)


def _source(commits: tuple[str, ...] = (SHA,)) -> RecordedCommitSource:
    """A commit source holding one real-shaped diff per commit."""
    return RecordedCommitSource(
        diffs={
            commit: CommitDiff(
                commit=commit,
                repository=REPOSITORY,
                files=((_file_diff("requests/sessions.py", [6, 7], []), POST_SOURCE, PRE_SOURCE),),
            )
            for commit in commits
        }
    )


class _BrokenSource:
    """Fails every fetch, the way a deleted repository does."""

    def fetch(self, reference: object) -> CommitDiff:
        msg = "repository not found"
        raise FetchError(msg)


def _row(engine: Engine, advisory_id: str) -> dict[str, object]:
    with engine.connect() as connection:
        return dict(
            connection.execute(
                select(
                    advisories.c.symbols_status,
                    advisories.c.symbols_detail,
                    advisories.c.symbols_attempts,
                    advisories.c.symbols_attempted_at,
                ).where(advisories.c.id == advisory_id)
            )
            .mappings()
            .one()
        )


def _symbols(engine: Engine, advisory_id: str) -> list[dict[str, object]]:
    with engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                select(vulnerable_symbols)
                .where(vulnerable_symbols.c.advisory_id == advisory_id)
                .order_by(vulnerable_symbols.c.symbol)
            )
            .mappings()
            .all()
        ]


# --- What it writes -------------------------------------------------------


def test_extraction_stores_the_symbols_a_fix_changed(clean: Engine) -> None:
    _insert(clean, f"{MARKER}CVE-2026-0001")

    report = _run(clean, source=_source())

    assert report.attempted == 1
    assert report.extracted == 1
    assert report.symbols_written >= 1

    stored = _symbols(clean, f"{MARKER}CVE-2026-0001")
    assert "requests.sessions.Session.send" in {row["symbol"] for row in stored}
    row = stored[0]
    assert row["ecosystem"] == "PyPI"
    assert row["package_name"] == "requests"
    assert row["source"] == "fix_commit"
    assert row["fix_commit"] == SHA
    assert row["file_path"] == "requests/sessions.py"
    assert row["confidence"] == Confidence.HIGH.value


def test_the_outcome_is_recorded_on_the_advisory(clean: Engine) -> None:
    _insert(clean, f"{MARKER}CVE-2026-0001")
    _run(clean, source=_source())

    row = _row(clean, f"{MARKER}CVE-2026-0001")
    assert row["symbols_status"] == SymbolsStatus.EXTRACTED.value
    assert row["symbols_attempts"] == 1
    assert row["symbols_attempted_at"] is not None
    # The reason travels with the row, so a finding left under investigation
    # can be explained without re-running anything.
    assert row["symbols_detail"]


def test_an_advisory_with_no_fix_reference_is_closed_not_retried(clean: Engine) -> None:
    _insert(clean, f"{MARKER}CVE-2026-0002", repository=None, commit=None)

    report = _run(clean, source=_source())

    assert report.found_nothing == 1
    row = _row(clean, f"{MARKER}CVE-2026-0002")
    # 'none' means extraction ran and legitimately found nothing, so the next
    # run must not fetch the same commit to reach the same conclusion.
    assert row["symbols_status"] == SymbolsStatus.NONE.value
    assert _run(clean, source=_source()).attempted == 0


def test_a_malicious_package_record_never_enters_the_queue(clean: Engine) -> None:
    """Measured on the real corpus, 12,003 of 19,552 PyPI records are these.

    They are the most recently modified, so they sort to the front. Discovering
    one network round trip at a time that a record with no fix has no fix would
    spend every batch before reaching a real advisory.
    """
    _insert(clean, f"MAL-{MARKER}MAL-2026-0001")

    report = _run(clean, source=_source())

    assert report.attempted == 0
    assert _symbols(clean, f"MAL-{MARKER}MAL-2026-0001") == []


def test_malicious_records_do_not_crowd_out_real_advisories(clean: Engine) -> None:
    for index in range(4):
        _insert(clean, f"MAL-{MARKER}CVE-2026-010{index}")
    _insert(clean, f"{MARKER}CVE-2026-0900")

    report = _run(clean, source=_source(), batch=2)

    assert report.attempted == 1
    assert report.extracted == 1
    assert _symbols(clean, f"{MARKER}CVE-2026-0900")


# --- Which advisories it picks -------------------------------------------


def test_a_withdrawn_advisory_is_never_worked_on(clean: Engine) -> None:
    """It produces no findings, so symbols for it would never be searched for."""
    _insert(clean, f"{MARKER}CVE-2026-0003", withdrawn=True)
    assert _run(clean, source=_source()).attempted == 0


def test_another_ecosystem_is_left_alone(clean: Engine) -> None:
    _insert(clean, f"{MARKER}CVE-2026-0004", ecosystem="npm", package="lodash")
    assert _run(clean, source=_source()).attempted == 0
    # And is still waiting, rather than marked done.
    assert _row(clean, f"{MARKER}CVE-2026-0004")["symbols_status"] == SymbolsStatus.PENDING.value


def test_an_already_extracted_advisory_is_not_redone(clean: Engine) -> None:
    _insert(clean, f"{MARKER}CVE-2026-0005", status=SymbolsStatus.EXTRACTED)
    assert _run(clean, source=_source()).attempted == 0


def test_an_advisory_affecting_several_packages_is_attempted_once(clean: Engine) -> None:
    """Otherwise one advisory fills several slots of the batch and is fetched
    once per package."""
    _insert(clean, f"{MARKER}CVE-2026-0006")
    with clean.begin() as connection:
        connection.execute(
            advisory_affected.insert().values(
                id=new_ulid(),
                advisory_id=f"{MARKER}CVE-2026-0006",
                ecosystem="PyPI",
                package_name="requests-extra",
                purl_base="pkg:pypi/requests-extra",
                ranges=[],
                versions=[],
                fixed_versions=[],
            )
        )

    report = _run(clean, source=_source())
    assert report.attempted == 1


def test_the_batch_size_is_respected(clean: Engine) -> None:
    for index in range(5):
        _insert(clean, f"{MARKER}CVE-2026-010{index}")

    first = _run(clean, source=_source(), batch=2)
    assert first.attempted == 2
    second = _run(clean, source=_source(), batch=2)
    assert second.attempted == 2
    assert _run(clean, source=_source(), batch=2).attempted == 1


def test_advisories_never_tried_come_before_ones_already_tried(clean: Engine) -> None:
    """Otherwise a handful of repeatedly failing advisories starve the queue."""
    _insert(clean, f"{MARKER}CVE-2026-0200", status=SymbolsStatus.FAILED, attempts=2)
    _insert(clean, f"{MARKER}CVE-2026-0201", attempts=0)

    _run(clean, source=_source(), batch=1)

    assert _row(clean, f"{MARKER}CVE-2026-0201")["symbols_attempts"] == 1
    assert _row(clean, f"{MARKER}CVE-2026-0200")["symbols_attempts"] == 2


# --- Failure and retry ---------------------------------------------------


def test_a_fetch_failure_is_recorded_and_retried(clean: Engine) -> None:
    _insert(clean, f"{MARKER}CVE-2026-0300")

    report = _run(clean, source=_BrokenSource())

    assert report.failed == 1
    assert f"{MARKER}CVE-2026-0300" in report.problems
    row = _row(clean, f"{MARKER}CVE-2026-0300")
    assert row["symbols_status"] == SymbolsStatus.FAILED.value
    assert row["symbols_attempts"] == 1
    assert "repository not found" in str(row["symbols_detail"])
    # Still in the queue, because the failure may have been transient.
    assert _run(clean, source=_BrokenSource()).attempted == 1


def test_retrying_stops_after_a_bounded_number_of_attempts(clean: Engine) -> None:
    """A fix commit in a deleted repository fails identically forever."""
    _insert(clean, f"{MARKER}CVE-2026-0301")

    for _ in range(MAX_ATTEMPTS):
        _run(clean, source=_BrokenSource())

    assert _row(clean, f"{MARKER}CVE-2026-0301")["symbols_attempts"] == MAX_ATTEMPTS
    assert _run(clean, source=_BrokenSource()).attempted == 0


def test_giving_up_is_reported_rather_than_silent(clean: Engine) -> None:
    _insert(clean, f"{MARKER}CVE-2026-0302", status=SymbolsStatus.FAILED, attempts=MAX_ATTEMPTS - 1)
    report = _run(clean, source=_BrokenSource())
    assert report.exhausted == 1


def test_an_unexpected_error_does_not_end_the_run(clean: Engine) -> None:
    """One malformed diff must not cost a crawl its remaining thousands."""

    class _Exploding:
        def fetch(self, reference: object) -> CommitDiff:
            raise RuntimeError("something nobody anticipated")

    _insert(clean, f"{MARKER}CVE-2026-0400")
    _insert(clean, f"{MARKER}CVE-2026-0401", repository="https://github.com/urllib3/urllib3")

    report = _run(clean, source=_Exploding())

    assert report.attempted == 2
    assert report.failed == 2
    assert all(
        "something nobody anticipated" in str(_row(clean, identifier)["symbols_detail"])
        for identifier in (f"{MARKER}CVE-2026-0400", f"{MARKER}CVE-2026-0401")
    )


# --- Re-running ----------------------------------------------------------


def test_re_extraction_replaces_rather_than_duplicates(clean: Engine) -> None:
    """A better builder may find different symbols in the same diff."""
    _insert(clean, f"{MARKER}CVE-2026-0500")
    _run(clean, source=_source())
    first = _symbols(clean, f"{MARKER}CVE-2026-0500")

    # Put it back in the queue, as a re-extraction campaign would.
    with clean.begin() as connection:
        connection.execute(
            update(advisories)
            .where(advisories.c.id == f"{MARKER}CVE-2026-0500")
            .values(symbols_status=SymbolsStatus.PENDING.value, symbols_attempts=0)
        )

    _run(clean, source=_source())
    second = _symbols(clean, f"{MARKER}CVE-2026-0500")

    assert len(second) == len(first)
    assert {row["symbol"] for row in second} == {row["symbol"] for row in first}


def test_work_already_done_survives_a_later_failure(clean: Engine) -> None:
    """The property that makes a crawl of this length resumable.

    Each advisory is committed as it is decided, so a job killed after the
    first has permanently done the first.
    """
    _insert(clean, f"{MARKER}CVE-2026-0600")
    _insert(clean, f"{MARKER}CVE-2026-0601", commit=OTHER_SHA)

    # Only the first commit is recorded, so the second advisory fails.
    report = _run(clean, source=_source(commits=(SHA,)))

    assert report.extracted == 1
    assert report.failed == 1
    assert _symbols(clean, f"{MARKER}CVE-2026-0600")
    assert _row(clean, f"{MARKER}CVE-2026-0600")["symbols_status"] == SymbolsStatus.EXTRACTED.value


# --- Reporting -----------------------------------------------------------


def test_the_backlog_can_be_counted(clean: Engine) -> None:
    _insert(clean, f"{MARKER}CVE-2026-0700")
    _insert(clean, f"{MARKER}CVE-2026-0701", status=SymbolsStatus.EXTRACTED)
    _insert(clean, f"{MARKER}CVE-2026-0702", status=SymbolsStatus.FAILED, attempts=MAX_ATTEMPTS)

    backlog = extraction_backlog(clean, advisory_ids=tuple(_CREATED))

    assert backlog.get(SymbolsStatus.PENDING.value) == 1
    assert backlog.get(SymbolsStatus.EXTRACTED.value) == 1
    assert backlog.get("exhausted") == 1


def test_an_empty_queue_is_not_an_error(clean: Engine) -> None:
    report = _run(clean, source=_source())
    assert report.attempted == 0
    assert report.summary_line()
