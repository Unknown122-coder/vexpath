"""CLI entry point.

Command groups are registered here and implemented under ``vexpath.commands``.
The exit-code contract in ``vexpath.exit_codes`` is the part CI depends on, and it
does not change between milestones.
"""

from __future__ import annotations

from typing import Annotated

import typer

from vexpath import __version__ as cli_version
from vexpath.commands import advisory as advisory_commands
from vexpath.commands import reach as reach_command
from vexpath.commands import sbom as sbom_commands
from vexpath.commands import scan as scan_command
from vexpath.output import OutputFormat, emit, emit_json
from vexpath_core import RESULTS_SCHEMA
from vexpath_core import __version__ as core_version
from vexpath_core.enums import NATIVE_LOCKFILE_ECOSYSTEMS, REACHABILITY_ECOSYSTEMS
from vexpath_core.sbom.lockfiles import LOCKFILE_PRIORITY

app = typer.Typer(
    name="vexpath",
    help=(
        "Find out which of your dependencies' known vulnerabilities are actually "
        "reachable, and prove it with signed VEX."
    ),
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode="rich",
)

app.add_typer(sbom_commands.app, name="sbom")
app.add_typer(advisory_commands.app, name="advisory")
app.command("scan")(scan_command.command)
app.command("reach")(reach_command.command)


@app.callback()
def cli() -> None:
    """Root callback.

    Present so that Typer keeps a command group rather than collapsing a
    single-command application into a bare entry point.
    """


@app.command()
def version(
    output: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format."),
    ] = OutputFormat.TABLE,
) -> None:
    """Print version and capability information.

    Capabilities are printed next to the version because a verdict means
    different things depending on what this build can analyse. Someone reading
    a report needs to know that without consulting documentation.
    """
    payload = {
        "cli": cli_version,
        "core": core_version,
        "results_schema": RESULTS_SCHEMA,
        "reachability_ecosystems": sorted(REACHABILITY_ECOSYSTEMS),
        "matching_ecosystems": "every ecosystem OSV publishes",
        "native_lockfile_ecosystems": sorted(NATIVE_LOCKFILE_ECOSYSTEMS),
        "lockfiles": list(LOCKFILE_PRIORITY),
        "reachability_available": True,
    }
    if output is OutputFormat.JSON:
        emit_json(payload)
        return

    lines = [
        f"{'vexpath':<16}{payload['cli']}",
        f"{'core':<16}{payload['core']}",
        f"{'results':<16}{payload['results_schema']}",
        "",
        f"matching        {payload['matching_ecosystems']}",
        f"lockfiles       {', '.join(LOCKFILE_PRIORITY)}",
        f"reachability    {', '.join(sorted(REACHABILITY_ECOSYSTEMS))}",
    ]
    emit("\n".join(lines) + "\n")


def run() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    run()
