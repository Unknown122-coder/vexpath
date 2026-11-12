"""Extract vulnerable symbols from advisories' fix commits.

This is the job that turns 88.7 % fix-commit coverage into symbols a
reachability search can look for. Without it, every finding reports
``no_fix_commit`` and nothing can ever be cleared, which makes the whole engine
behind it worthless.

It is a long-running, network-bound crawl over tens of thousands of
repositories, so it is built to be stopped and resumed rather than to finish in
one go. Three properties make that work:

**Progress lives in the database, not in memory.** Each advisory's outcome is
committed as it is decided. A job killed halfway has done half the work
permanently, and the next run picks up where it stopped.

**Every advisory is attempted a bounded number of times.** A fix commit in a
deleted repository fails identically forever. Counting attempts is what stops
it being retried on every run while advisories never tried once wait behind it.

**One repository is fetched at a time per host.** Advisories are processed in
repository order so that several advisories sharing a repository reuse one
fetch, and the crawl does not open a connection per advisory.

Nothing that is analysed is ever executed. The commit is fetched into a bare
repository with no checkout, hooks disabled, and the diff read as text.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, RowMapping, and_, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from vexpath_core.enums import SymbolsStatus
from vexpath_core.ids import new_ulid
from vexpath_core.models.advisory import Advisory, AffectedPackage
from vexpath_core.patchdiff import GitCommitSource, extract_for_advisory
from vexpath_core.patchdiff.fetch import CommitSource
from vexpath_core.patchdiff.pipeline import PatchDiffResult
from vexpath_db.tables import advisories, advisory_affected, vulnerable_symbols
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

#: After this many attempts an advisory stops being retried. A fix commit in a
#: deleted repository fails the same way every time, and the queue is better
#: spent on advisories never tried.
MAX_ATTEMPTS = 3

#: How many advisories one run processes. Bounded so a scheduled job finishes
#: in a predictable window and a failure costs one window, not a whole crawl.
DEFAULT_BATCH = 500

#: Statuses that mean "there is still work to do here". ``none`` is excluded
#: deliberately: extraction ran and legitimately found nothing, so retrying it
#: would fetch the same commit to reach the same conclusion.
RETRYABLE = (SymbolsStatus.PENDING, SymbolsStatus.FAILED)


@dataclass(slots=True)
class ExtractReport:
    """What one extraction run did."""

    attempted: int = 0
    extracted: int = 0
    symbols_written: int = 0
    found_nothing: int = 0
    still_pending: int = 0
    failed: int = 0
    exhausted: int = 0
    repositories: int = 0
    #: Advisory identifier to the reason, for the ones that did not succeed.
    problems: dict[str, str] = field(default_factory=dict)

    @property
    def success_ratio(self) -> float:
        return self.extracted / self.attempted if self.attempted else 0.0

    def summary_line(self) -> str:
        parts = [
            f"{self.attempted} advisories attempted",
            f"{self.extracted} extracted",
            f"{self.symbols_written} symbols",
            f"{self.repositories} repositories",
        ]
        if self.found_nothing:
            parts.append(f"{self.found_nothing} had nothing to extract")
        if self.still_pending:
            parts.append(f"{self.still_pending} need a reference resolved")
        if self.failed:
            parts.append(f"{self.failed} failed")
        if self.exhausted:
            parts.append(f"{self.exhausted} gave up after {MAX_ATTEMPTS} attempts")
        return ", ".join(parts)


def extract_symbols(
    engine: Engine,
    *,
    ecosystem: str = "PyPI",
    batch: int = DEFAULT_BATCH,
    advisory_ids: Sequence[str] | None = None,
    source: CommitSource | None = None,
    cache_root: Path | None = None,
    retry_exhausted: bool = False,
) -> ExtractReport:
    """Extract symbols for the next batch of advisories awaiting them.

    Args:
        engine: Database holding the advisory corpus.
        ecosystem: Only advisories affecting this ecosystem are processed,
            because symbol names are ecosystem-specific and the extractor is
            Python-only (ADR-0012).
        batch: How many advisories to attempt in this run.
        advisory_ids: Work only on these advisories, instead of taking the
            next batch off the queue. This is how a specific advisory is
            re-extracted after the builder improves, and how a report of a
            wrong symbol is investigated. The retry cap and the other queue
            rules still apply, so a named advisory that has already been given
            up on stays given up on.
        source: Where commits come from. Defaults to fetching over the network.
            Injected so tests run offline against recorded diffs.
        retry_exhausted: Put advisories the queue gave up on back in it, by
            clearing their attempt counter. For when the extractor gains a
            capability, not for when somebody is impatient: a run that failed
            because nothing could resolve a release tag is not evidence about
            a build that can. Off by default, because a deleted repository
            fails identically for ever and retrying it costs a fetch each
            time.
        cache_root: Where bare repositories are kept between fetches, so that
            advisories sharing a repository cost one fetch rather than several.

    Returns:
        A report of what the run did. Partial progress is already committed, so
        the report describes work that has persisted even if a later advisory
        raised.
    """
    commit_source = source if source is not None else GitCommitSource(cache_root=cache_root)
    report = ExtractReport()

    if retry_exhausted:
        revived = _reset_exhausted(engine, ecosystem)
        log.info("advisory.patchdiff.retry_exhausted", ecosystem=ecosystem, advisories=revived)

    queued = _claim(engine, ecosystem=ecosystem, batch=batch, advisory_ids=advisory_ids)
    if not queued:
        log.info("advisory.patchdiff.idle", ecosystem=ecosystem)
        return report

    log.info(
        "advisory.patchdiff.start",
        ecosystem=ecosystem,
        advisories=len(queued),
        repositories=len({advisory.repo_url or "" for advisory in queued}),
    )

    for repository, group in _by_repository(queued):
        report.repositories += 1
        for advisory in group:
            result = _attempt(commit_source, advisory, ecosystem, report)
            _record(engine, advisory, result, ecosystem=ecosystem, report=report)

        log.debug(
            "advisory.patchdiff.repository_done",
            repository=repository,
            advisories=len(group),
        )

    log.info("advisory.patchdiff.done", summary=report.summary_line())
    return report


def _attempt(
    source: CommitSource, advisory: Advisory, ecosystem: str, report: ExtractReport
) -> PatchDiffResult:
    """Run extraction for one advisory, converting a crash into a failure.

    A single malformed diff or an unexpected error from one repository must not
    end a crawl that has thousands of advisories left, so anything unforeseen
    is recorded against that advisory and the run continues.
    """
    report.attempted += 1
    try:
        return extract_for_advisory(advisory, source, ecosystem=ecosystem)
    except Exception as exc:  # noqa: BLE001 - one advisory must not end the crawl
        log.warning(
            "advisory.patchdiff.unexpected_error",
            advisory_id=advisory.id,
            error=f"{type(exc).__name__}: {exc}",
        )
        return PatchDiffResult(
            advisory_id=advisory.id,
            status=SymbolsStatus.FAILED,
            detail=f"Extraction raised {type(exc).__name__}: {exc}",
        )


def _by_repository(queued: Sequence[Advisory]) -> Iterator[tuple[str, list[Advisory]]]:
    """Group advisories by upstream repository.

    Several advisories often share a repository. Fetching it once and reading
    several commits out of it is the difference between one clone and twenty.
    """
    grouped: dict[str, list[Advisory]] = defaultdict(list)
    for advisory in queued:
        grouped[advisory.repo_url or ""].append(advisory)
    for repository in sorted(grouped):
        yield repository, grouped[repository]


def _reset_exhausted(engine: Engine, ecosystem: str) -> int:
    """Clear the attempt counter on advisories the queue has retired.

    Scoped to those still awaiting symbols: one already extracted, or
    recorded as having nothing to extract, is not waiting for another go.
    """
    affected = (
        select(advisory_affected.c.advisory_id)
        .where(advisory_affected.c.ecosystem == ecosystem)
        .scalar_subquery()
    )
    with engine.begin() as connection:
        result = connection.execute(
            update(advisories)
            .where(
                and_(
                    advisories.c.symbols_status == SymbolsStatus.PENDING.value,
                    advisories.c.symbols_attempts >= MAX_ATTEMPTS,
                    advisories.c.id.in_(affected),
                )
            )
            .values(symbols_attempts=0)
        )
    return int(result.rowcount or 0)


def _claim(
    engine: Engine,
    *,
    ecosystem: str,
    batch: int,
    advisory_ids: Sequence[str] | None = None,
) -> list[Advisory]:
    """Read the next advisories needing extraction.

    Ordered by attempt count so nothing is tried a second time while something
    else waits for its first, then by modification date so recent advisories,
    which are the ones people are currently being alerted about, come first.

    Withdrawn advisories are excluded: they produce no findings, so symbols for
    them would never be searched for.
    """
    # The advisories to work on are chosen first, then their affected packages
    # are read. Selecting both at once would return one row per affected
    # package, and an advisory affecting four packages would fill four of the
    # batch's slots and be extracted four times.
    restricted = [advisories.c.id.in_(list(advisory_ids))] if advisory_ids is not None else []
    chosen = (
        select(advisories.c.id)
        .select_from(
            advisories.join(advisory_affected, advisories.c.id == advisory_affected.c.advisory_id)
        )
        .where(
            and_(
                *restricted,
                advisory_affected.c.ecosystem == ecosystem,
                advisories.c.withdrawn_at.is_(None),
                advisories.c.symbols_status.in_([status.value for status in RETRYABLE]),
                advisories.c.symbols_attempts < MAX_ATTEMPTS,
                # Malicious-package records have no fix to diff. Advisories
                # loaded by a build that did not record that are skipped here
                # rather than being rediscovered one network round trip at a
                # time.
                advisories.c.id.not_like("MAL-%"),
            )
        )
        .group_by(advisories.c.id, advisories.c.symbols_attempts, advisories.c.modified_at)
        .order_by(
            advisories.c.symbols_attempts.asc(),
            advisories.c.modified_at.desc().nulls_last(),
            advisories.c.id.asc(),
        )
        .limit(batch)
    )

    with engine.connect() as connection:
        identifiers = [row[0] for row in connection.execute(chosen)]
        if not identifiers:
            return []

        rows = (
            connection.execute(
                select(
                    advisories.c.id,
                    advisories.c.aliases,
                    advisories.c.summary,
                    advisories.c.repo_url,
                    advisories.c.references,
                    advisory_affected.c.ecosystem,
                    advisory_affected.c.package_name,
                    advisory_affected.c.purl_base,
                    advisory_affected.c.ranges,
                )
                .select_from(
                    advisories.join(
                        advisory_affected, advisories.c.id == advisory_affected.c.advisory_id
                    )
                )
                .where(
                    and_(
                        advisories.c.id.in_(identifiers),
                        advisory_affected.c.ecosystem == ecosystem,
                    )
                )
                .order_by(advisory_affected.c.package_name.asc())
            )
            .mappings()
            .all()
        )

    order = {identifier: position for position, identifier in enumerate(identifiers)}
    grouped = _group_rows(rows)
    return sorted(grouped, key=lambda advisory: order[advisory.id])


def _group_rows(rows: Sequence[RowMapping]) -> list[Advisory]:
    """Rebuild one advisory per identifier, with every affected package on it.

    Only the fields the extractor reads: the identifiers, the repository, the
    references a fix commit is resolved from, and the affected packages.
    Loading whole advisories would move megabytes of details and CVSS vectors
    that nothing here looks at.
    """
    packages: dict[str, list[AffectedPackage]] = defaultdict(list)
    header: dict[str, RowMapping] = {}
    for row in rows:
        identifier = str(row["id"])
        header.setdefault(identifier, row)
        packages[identifier].append(
            AffectedPackage.model_validate(
                {
                    "ecosystem": row["ecosystem"],
                    "name": row["package_name"],
                    "purl_base": row["purl_base"],
                    "ranges": row["ranges"] or (),
                }
            )
        )

    return [
        Advisory.model_validate(
            {
                "id": identifier,
                "aliases": row["aliases"] or (),
                "summary": row["summary"] or "",
                "repo_url": row["repo_url"],
                "references": row["references"] or (),
                "affected": packages[identifier],
            }
        )
        for identifier, row in header.items()
    ]


def _record(
    engine: Engine,
    advisory: Advisory,
    result: PatchDiffResult,
    *,
    ecosystem: str,
    report: ExtractReport,
) -> None:
    """Write one advisory's outcome, and its symbols if it found any.

    Committed per advisory rather than per batch. A crawl that is killed after
    four hundred advisories has permanently done four hundred advisories'
    worth of work, which is the property that makes a job of this length
    resumable at all.
    """
    now = datetime.now(UTC)
    status = result.status
    attempts_exhausted = False

    if status is SymbolsStatus.EXTRACTED:
        report.extracted += 1
    elif status is SymbolsStatus.NONE:
        report.found_nothing += 1
    elif status is SymbolsStatus.PENDING:
        report.still_pending += 1
        report.problems[advisory.id] = result.detail
    else:
        report.failed += 1
        report.problems[advisory.id] = result.detail

    with engine.begin() as connection:
        if result.symbols:
            rows = [
                {
                    "id": new_ulid(),
                    "advisory_id": advisory.id,
                    "ecosystem": symbol.ecosystem,
                    "package_name": symbol.package_name,
                    "symbol": symbol.symbol,
                    "kind": symbol.kind.value,
                    "source": symbol.source.value,
                    "confidence": symbol.confidence.value,
                    "file_path": symbol.file_path,
                    "fix_commit": symbol.fix_commit,
                }
                for symbol in result.symbols
            ]
            statement = pg_insert(vulnerable_symbols).values(rows)
            # Re-running extraction for the same advisory must replace what it
            # said last time rather than fail or duplicate: a better builder
            # may find different symbols in the same diff.
            connection.execute(
                statement.on_conflict_do_update(
                    index_elements=["advisory_id", "package_name", "symbol"],
                    set_={
                        "kind": statement.excluded.kind,
                        "source": statement.excluded.source,
                        "confidence": statement.excluded.confidence,
                        "file_path": statement.excluded.file_path,
                        "fix_commit": statement.excluded.fix_commit,
                    },
                )
            )
            report.symbols_written += len(rows)

        attempts = advisories.c.symbols_attempts + 1
        connection.execute(
            update(advisories)
            .where(advisories.c.id == advisory.id)
            .values(
                symbols_status=status.value,
                symbols_detail=result.detail or None,
                symbols_attempts=attempts,
                symbols_attempted_at=now,
            )
        )

        if status in RETRYABLE:
            current = connection.execute(
                select(advisories.c.symbols_attempts).where(advisories.c.id == advisory.id)
            ).scalar_one()
            attempts_exhausted = current >= MAX_ATTEMPTS

    if attempts_exhausted:
        report.exhausted += 1
        log.info(
            "advisory.patchdiff.gave_up",
            advisory_id=advisory.id,
            ecosystem=ecosystem,
            attempts=MAX_ATTEMPTS,
            detail=result.detail,
        )


def extraction_backlog(
    engine: Engine, *, ecosystem: str = "PyPI", advisory_ids: Sequence[str] | None = None
) -> dict[str, int]:
    """Count what is waiting, what is done, and what was given up on.

    The ratio of ``extracted`` to the rest is the number the product's
    usefulness rests on, so it is cheap to ask for and reported by the job.
    """
    restricted = [advisories.c.id.in_(list(advisory_ids))] if advisory_ids is not None else []
    query = (
        select(
            advisories.c.symbols_status,
            func.count().label("total"),
        )
        .select_from(
            advisories.join(advisory_affected, advisories.c.id == advisory_affected.c.advisory_id)
        )
        .where(
            and_(
                *restricted,
                advisory_affected.c.ecosystem == ecosystem,
                advisories.c.withdrawn_at.is_(None),
            )
        )
        .group_by(advisories.c.symbols_status)
    )
    counts: dict[str, int] = {}
    with engine.connect() as connection:
        for row in connection.execute(query):
            counts[str(row.symbols_status)] = int(row.total)

    exhausted = (
        select(func.count())
        .select_from(
            advisories.join(advisory_affected, advisories.c.id == advisory_affected.c.advisory_id)
        )
        .where(
            and_(
                *restricted,
                advisory_affected.c.ecosystem == ecosystem,
                advisories.c.symbols_status.in_([status.value for status in RETRYABLE]),
                advisories.c.symbols_attempts >= MAX_ATTEMPTS,
            )
        )
    )
    with engine.connect() as connection:
        counts["exhausted"] = connection.execute(exhausted).scalar_one()

    return counts


__all__ = [
    "DEFAULT_BATCH",
    "MAX_ATTEMPTS",
    "RETRYABLE",
    "ExtractReport",
    "extract_symbols",
    "extraction_backlog",
]
