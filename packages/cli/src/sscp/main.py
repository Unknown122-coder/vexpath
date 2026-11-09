"""CLI entry point.

Command groups are registered here and implemented in sibling modules as each
milestone lands. The skeleton exists from M0 so that the exit-code contract,
the output-format flag and the help text are settled before any analysis code
depends on them.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

import typer
from rich.console import Console

from sscp import __version__ as cli_version
from sscp_core import RESULTS_SCHEMA
from sscp_core import __version__ as core_version
from sscp_core.enums import REACHABILITY_ECOSYSTEMS


class OutputFormat(StrEnum):
    """How to render results.

    ``json`` is the machine contract consumed by the GitHub Action and the
    platform upload endpoint; the others are for people.
    """

    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


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

# Written to stdout; diagnostics go to stderr so that `sscp ... > out.json`
# stays valid JSON.
out = Console()
err = Console(stderr=True)


@app.callback()
def cli() -> None:
    """Root callback.

    Present so that Typer keeps a command group rather than collapsing a
    single-command application into a bare entry point. Without it, ``sscp``
    would silently become an alias for whichever command happened to be the
    only one registered.
    """


@app.command()
def version(
    output: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format."),
    ] = OutputFormat.TABLE,
) -> None:
    """Print version and capability information.

    Capabilities are printed alongside the version because a verdict means
    different things depending on which ecosystems this build can analyse.
    """
    payload = {
        "cli": cli_version,
        "core": core_version,
        "results_schema": RESULTS_SCHEMA,
        "reachability_ecosystems": sorted(REACHABILITY_ECOSYSTEMS),
    }
    if output is OutputFormat.JSON:
        import json

        out.print_json(json.dumps(payload))
        return

    out.print(f"sscp        {payload['cli']}")
    out.print(f"core        {payload['core']}")
    out.print(f"results     {payload['results_schema']}")
    out.print(f"reachability for {', '.join(payload['reachability_ecosystems'])}")


def run() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    run()
