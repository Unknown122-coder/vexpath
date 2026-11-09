"""Worker command-line entry point.

Every job is a command. Scheduled work runs through a cron trigger that invokes
these commands, which is how the reference deployment schedules the advisory
sync (see ``docs/01-architecture.md`` section 7.1) and how CI exercises them.

A queue (ADR-0003) is introduced when the first user-triggered job arrives in
M4. Until something enqueues work, a worker loop would have nothing to consume.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vexpath_core.advisory.sync import DEFAULT_ECOSYSTEMS, AdvisorySyncError
from vexpath_core.snapshot import SnapshotIntegrityError
from vexpath_db.engine import create_sync_engine
from vexpath_platform.logging import configure_logging, get_logger
from vexpath_platform.settings import get_settings
from vexpath_worker import __version__
from vexpath_worker.jobs.extract_symbols import (
    DEFAULT_BATCH,
    extract_symbols,
    extraction_backlog,
)
from vexpath_worker.jobs.seed_advisories import seed_snapshot
from vexpath_worker.jobs.sync_advisories import refresh_advisories

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


@app.command()
def version() -> None:
    """Print the worker version."""
    typer.echo(__version__)


def run() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    run()
