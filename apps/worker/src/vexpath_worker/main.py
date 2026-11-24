"""Worker command-line entry point.

Every job is a command. Scheduled work runs through a cron trigger that invokes
these commands, which is how the reference deployment schedules the advisory
sync (see ``docs/01-architecture.md`` section 7.1) and how CI exercises them.

A queue (ADR-0003) is introduced when the first user-triggered job arrives in
M4. Until something enqueues work, a worker loop would have nothing to consume.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from vexpath_core import __version__ as core_version
from vexpath_core.advisory.sync import DEFAULT_ECOSYSTEMS, AdvisorySyncError
from vexpath_core.corpus import merge
from vexpath_core.ids import new_ulid
from vexpath_core.models.advisory import AdvisorySnapshot
from vexpath_core.snapshot import SnapshotIntegrityError, read_snapshot, write_snapshot
from vexpath_db.engine import create_sync_engine
from vexpath_platform.logging import configure_logging, get_logger
from vexpath_platform.settings import get_settings
from vexpath_worker import __version__
from vexpath_worker.jobs.enrich_advisories import refresh_signals
from vexpath_worker.jobs.export_snapshot import export_snapshot
from vexpath_worker.jobs.extract_symbols import (
    DEFAULT_BATCH,
    extract_symbols,
    extraction_backlog,
)
from vexpath_worker.jobs.seed_advisories import seed_snapshot
from vexpath_worker.jobs.sync_advisories import refresh_advisories

#: How far symbol coverage may fall across a refresh before it is
#: refused. Not zero tolerance: advisories get withdrawn and upstream
#: repositories get renamed, and each legitimately drops symbols. A
#: tenth is far more than either explains and far less than a wipe.
SYMBOL_FLOOR = 0.9

log = get_logger(__name__)

app = typer.Typer(
    name="vexpath-worker",
    help="Background jobs for the supply-chain security platform.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command("seed-advisories")
def seed_advisories(
    directory: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            dir_okay=True,
            help="Snapshot directory holding snapshot.json and advisories.jsonl.",
        ),
    ],
) -> None:
    """Load a frozen advisory snapshot into the database."""
    settings = get_settings()
    configure_logging(settings)
    engine = create_sync_engine(settings.database_url)
    try:
        report = seed_snapshot(engine, directory)
    except SnapshotIntegrityError as exc:
        # A corrupted advisory corpus changes verdicts, so this is fatal rather
        # than a warning to be worked around.
        typer.secho(f"snapshot integrity check failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    finally:
        engine.dispose()
    typer.echo(report.summary_line())


@app.command("sync-advisories")
def sync_advisories(
    directory: Annotated[
        Path,
        typer.Argument(help="Where to write the snapshot."),
    ] = Path("var/advisories"),
    ecosystems: Annotated[
        str,
        typer.Option("--ecosystem", "-e", help="Comma-separated OSV ecosystem names."),
    ] = ",".join(DEFAULT_ECOSYSTEMS),
    load: Annotated[
        bool,
        typer.Option(
            "--load/--no-load",
            help=(
                "Load the downloaded snapshot into the database. Turn it off to "
                "publish a snapshot artefact without needing a database."
            ),
        ),
    ] = True,
    fail_on_low_coverage: Annotated[
        bool,
        typer.Option(
            "--fail-on-low-coverage",
            help=(
                "Exit non-zero when an ecosystem's symbol coverage is below the "
                "floor. Useful as an early warning in a scheduled job."
            ),
        ),
    ] = False,
) -> None:
    """Download a fresh advisory corpus and write it as a snapshot.

    This is the job that keeps the corpus current. It also measures symbol
    coverage, which is the number that decides whether reachability analysis
    can clear enough findings to be worth its engine.
    """
    settings = get_settings()
    configure_logging(settings)
    names = [name.strip() for name in ecosystems.split(",") if name.strip()]
    if not names:
        typer.secho("no ecosystems given", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=3)

    engine = create_sync_engine(settings.database_url) if load else None
    try:
        report = refresh_advisories(directory, engine=engine, ecosystems=names)
    except AdvisorySyncError as exc:
        typer.secho(f"advisory sync failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    except SnapshotIntegrityError as exc:
        typer.secho(f"snapshot integrity check failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    finally:
        if engine is not None:
            engine.dispose()

    typer.echo(report.summary_line())
    for concern in report.coverage_concerns:
        typer.secho(concern, fg=typer.colors.YELLOW, err=True)
    if fail_on_low_coverage and report.coverage_concerns:
        raise typer.Exit(code=1)


@app.command("extract-symbols")
def extract_symbols_command(
    ecosystem: Annotated[
        str,
        typer.Option(
            "--ecosystem",
            "-e",
            help="Which ecosystem to extract for. Only PyPI is implemented (ADR-0012).",
        ),
    ] = "PyPI",
    batch: Annotated[
        int,
        typer.Option(
            "--batch",
            "-n",
            min=1,
            help=(
                "How many advisories to attempt. Bounded so a scheduled run "
                "finishes in a predictable window."
            ),
        ),
    ] = DEFAULT_BATCH,
    cache_root: Annotated[
        Path | None,
        typer.Option(
            "--cache-root",
            file_okay=False,
            help=(
                "Where to keep bare repositories between fetches. Reusing one "
                "across runs turns most fetches into incremental ones."
            ),
        ),
    ] = None,
    advisory: Annotated[
        str | None,
        typer.Option(
            "--advisory",
            "-a",
            help=(
                "Comma-separated advisory identifiers to work on, instead of "
                "taking the next batch off the queue. This is how one advisory "
                "is re-extracted after the builder improves."
            ),
        ),
    ] = None,
    show_backlog: Annotated[
        bool,
        typer.Option("--backlog/--no-backlog", help="Print what is still waiting afterwards."),
    ] = True,
    retry_exhausted: Annotated[
        bool,
        typer.Option(
            "--retry-exhausted",
            help=(
                "Put advisories the queue gave up on back in it. For after the "
                "extractor gains a capability: a run that failed because nothing "
                "could resolve a release tag says nothing about a build that can."
            ),
        ),
    ] = False,
) -> None:
    """Extract vulnerable symbols from advisories' fix commits.

    This is what turns an advisory into something a reachability search can
    look for. Without it every finding reports no_fix_commit and nothing can
    ever be cleared.

    The run is bounded and resumable: each advisory's outcome is committed as
    it is decided, so stopping this job costs the advisory in flight and
    nothing else. Run it repeatedly until the backlog stops shrinking.

    It reaches the network, fetching each fix commit into a bare repository
    with no checkout and hooks disabled. Nothing from a fetched repository is
    ever executed.
    """
    settings = get_settings()
    configure_logging(settings)
    named = [entry.strip() for entry in (advisory or "").split(",") if entry.strip()]
    engine = create_sync_engine(settings.database_url)
    try:
        report = extract_symbols(
            engine,
            ecosystem=ecosystem,
            batch=batch,
            advisory_ids=named or None,
            cache_root=cache_root,
            retry_exhausted=retry_exhausted,
        )
        typer.echo(report.summary_line())
        if show_backlog:
            backlog = extraction_backlog(engine, ecosystem=ecosystem)
            typer.echo(
                "backlog: "
                + ", ".join(f"{state} {count}" for state, count in sorted(backlog.items()))
            )
    finally:
        engine.dispose()

    for advisory_id, reason in sorted(report.problems.items())[:10]:
        typer.secho(f"{advisory_id}: {reason}", fg=typer.colors.YELLOW, err=True)


@app.command("refresh-corpus")
def refresh_corpus_command(
    previous: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            dir_okay=True,
            help="The corpus being replaced: the published one, with its symbols.",
        ),
    ],
    directory: Annotated[
        Path,
        typer.Argument(help="Where to write the merged corpus."),
    ] = Path("var/refreshed"),
    ecosystems: Annotated[
        str,
        typer.Option("--ecosystem", "-e", help="Comma-separated OSV ecosystem names."),
    ] = "PyPI",
) -> None:
    """Download fresh advisories and keep the symbols already extracted.

    The step that lets a corpus refresh itself. Advisories go stale -- a
    vulnerability disclosed today is invisible until the corpus is rebuilt --
    but a naive rebuild is far worse than a stale corpus: OSV publishes no
    vulnerable symbols, and loading a fresh download into the database deletes
    every one that was extracted. Hours of work gone, and nothing fails. The
    corpus still parses, still verifies, still publishes, and then decides
    nothing for everybody who downloads it.

    So this writes a snapshot and never touches the database: fresh advisories
    from OSV, with the previous corpus's symbols carried onto the advisories
    that still lack them. :func:`vexpath_core.corpus.merge` holds the rules and
    the reasons for each.

    What comes out has current advisories and at least the symbol coverage it
    started with. Seed it, run extraction to fill the new gaps, export, and
    publish.
    """
    settings = get_settings()
    configure_logging(settings)

    names = [name.strip() for name in ecosystems.split(",") if name.strip()]
    _, inherited = read_snapshot(previous)

    downloaded_into = directory.parent / f"{directory.name}-downloaded"
    refresh_advisories(downloaded_into, ecosystems=names or DEFAULT_ECOSYSTEMS)
    _, downloaded = read_snapshot(downloaded_into)

    merged, merge_report = merge(downloaded, inherited)
    typer.echo(merge_report.summary_line())

    # Refused rather than written. A corpus with fewer symbols than the one it
    # replaces is the failure this command exists to prevent, and publishing
    # one would un-decide findings for every install that downloaded it.
    # Withdrawals and repository changes can account for a small drop, which is
    # why this compares totals rather than demanding they never fall.
    before = sum(len(advisory.symbols) for advisory in inherited)
    after = sum(len(advisory.symbols) for advisory in merged)
    if after < before * SYMBOL_FLOOR:
        typer.secho(
            f"refusing to write a corpus with {after} symbols where the one it "
            f"replaces has {before}. Withdrawn advisories and repository changes "
            f"explain a small drop; this is not small.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    written = write_snapshot(
        directory,
        AdvisorySnapshot(
            id=new_ulid(),
            created_at=datetime.now(UTC),
            # Filled in by the writer, which hashes the records it writes.
            content_sha256="0" * 64,
            core_version=core_version,
            ecosystems=names,
            counts={},
        ),
        merged,
    )
    with_symbols = sum(1 for advisory in merged if advisory.symbols)
    typer.echo(
        f"wrote {directory}: {after} symbols across {with_symbols} advisories, "
        f"snapshot {written.id}"
    )


@app.command("export-snapshot")
def export_snapshot_command(
    directory: Annotated[
        Path,
        typer.Argument(help="Where to write the snapshot."),
    ] = Path("var/enriched"),
    ecosystems: Annotated[
        str | None,
        typer.Option(
            "--ecosystem",
            "-e",
            help="Comma-separated ecosystems to include. Defaults to all of them.",
        ),
    ] = None,
    only_with_symbols: Annotated[
        bool,
        typer.Option(
            "--only-with-symbols",
            help=(
                "Write only advisories that have symbols. Smaller, but not a "
                "substitute for the full corpus: an advisory missing from a "
                "snapshot produces no finding at all."
            ),
        ),
    ] = False,
) -> None:
    """Write the database's corpus out as a snapshot, symbols included.

    This is the step that gets extracted symbols to the tool that needs them.
    A downloaded corpus carries no vulnerable symbols, because OSV does not
    publish them; extraction fills them in but writes to the database, and the
    command-line tool reads a snapshot directory.

    So a deployment runs sync, extract, export, publish, and what it publishes
    is a corpus with symbols in it.
    """
    settings = get_settings()
    configure_logging(settings)
    names = [name.strip() for name in (ecosystems or "").split(",") if name.strip()]
    engine = create_sync_engine(settings.database_url)
    try:
        report = export_snapshot(
            engine,
            directory,
            ecosystems=names or None,
            only_with_symbols=only_with_symbols,
        )
    finally:
        engine.dispose()
    typer.echo(report.summary_line())


@app.command("enrich-advisories")
def enrich_advisories_command(
    fail_on_missing_feed: Annotated[
        bool,
        typer.Option(
            "--fail-on-missing-feed",
            help=(
                "Exit non-zero when a feed could not be read. Off by default: "
                "the corpus is still correct without a prioritisation signal."
            ),
        ),
    ] = False,
) -> None:
    """Refresh EPSS probabilities and CISA KEV membership over the corpus.

    EPSS is recomputed daily; the advisory corpus is not. Re-downloading the
    OSV exports to pick up new probabilities would be the wrong trade, so this
    updates the two signal columns in place and nothing else.

    These signals change what to fix first, never what is reported. A feed
    being unavailable is reported rather than fatal.
    """
    settings = get_settings()
    configure_logging(settings)
    engine = create_sync_engine(settings.database_url)
    try:
        report = refresh_signals(engine)
    finally:
        engine.dispose()

    typer.echo(report.summary_line())
    for failure in report.failures:
        typer.secho(failure, fg=typer.colors.YELLOW, err=True)
    if fail_on_missing_feed and report.failures:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the worker version."""
    typer.echo(__version__)


def run() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    run()
