"""CLI entry point.

Command groups are registered here and implemented under ``sscp.commands``.
The exit-code contract in ``sscp.exit_codes`` is the part CI depends on, and it
does not change between milestones.
"""

from __future__ import annotations

from typing import Annotated

import typer

from sscp import __version__ as cli_version
from sscp.commands import advisory as advisory_commands
from sscp.commands import sbom as sbom_commands
from sscp.commands import scan as scan_command
from sscp.output import OutputFormat, emit, emit_json
from sscp_core import RESULTS_SCHEMA
from sscp_core import __version__ as core_version
from sscp_core.enums import NATIVE_LOCKFILE_ECOSYSTEMS, REACHABILITY_ECOSYSTEMS
from sscp_core.sbom.lockfiles import LOCKFILE_PRIORITY

app = typer.Typer(
    name="sscp",
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
        "reachability_available": False,
    }
    if output is OutputFormat.JSON:
        emit_json(payload)
        return

    lines = [
        f"sscp        {payload['cli']}",
        f"core        {payload['core']}",
        f"results     {payload['results_schema']}",
        "",
        f"matching        {payload['matching_ecosystems']}",
        f"lockfiles       {', '.join(LOCKFILE_PRIORITY)}",
        f"reachability    {', '.join(sorted(REACHABILITY_ECOSYSTEMS))} "
        f"(not available in this build)",
    ]
    emit("\n".join(lines) + "\n")


def run() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    run()
