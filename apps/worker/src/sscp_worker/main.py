"""Worker command-line entry point.

Jobs are runnable as commands from the start. The queue (ADR-0003) is wired up
in M1 with the first scheduled job; a worker loop with nothing to consume would
prove nothing, so until then the same job functions are invoked directly, which
is also how they are exercised in CI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sscp_core.snapshot import SnapshotIntegrityError
from sscp_db.engine import create_sync_engine
from sscp_platform.logging import configure_logging, get_logger
from sscp_platform.settings import get_settings
from sscp_worker import __version__
from sscp_worker.jobs.seed_advisories import seed_snapshot

log = get_logger(__name__)

app = typer.Typer(
    name="sscp-worker",
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


@app.command()
def version() -> None:
    """Print the worker version."""
    typer.echo(__version__)


def run() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    run()
