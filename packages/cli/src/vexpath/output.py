"""Output handling shared by every command.

Two rules hold throughout:

Machine output goes to standard output and nothing else does. ``vexpath scan
--format json > results.json`` has to produce a file that parses, so progress,
warnings and errors all go to standard error.

Failures name the fix. A tool that runs in CI is read by someone who did not
choose to run it and does not know its internals, so every error says what to
do next.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any, NoReturn

import typer
from rich.console import Console

from vexpath.exit_codes import ExitCode

#: Machine-readable output only.
stdout = Console(soft_wrap=True)
#: Everything a human reads while the command runs.
stderr = Console(stderr=True, soft_wrap=True)


class OutputFormat(StrEnum):
    """How to render results."""

    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"

    @property
    def is_machine_readable(self) -> bool:
        return self in {OutputFormat.JSON, OutputFormat.SARIF}


def emit(text: str) -> None:
    """Write rendered output to standard output, unstyled.

    Markup interpretation is off: advisory summaries and component names come
    from outside this process, and a square bracket in one of them must not be
    read as a style tag.
    """
    stdout.print(text, markup=False, highlight=False, end="")


def emit_json(payload: Any) -> None:
    """Write a JSON document to standard output."""
    stdout.print(json.dumps(payload, indent=2, default=str), markup=False, highlight=False)


def note(message: str) -> None:
    """Report progress to standard error."""
    stderr.print(f"[dim]{message}[/dim]")


def warn(message: str) -> None:
    """Report something the user should know but that is not fatal."""
    stderr.print(f"[yellow]warning[/yellow] {message}")


def fail(message: str, *, code: ExitCode = ExitCode.ANALYSIS_ERROR) -> NoReturn:
    """Report a failure and exit.

    The default is an analysis error rather than a policy failure, because the
    two must stay distinguishable: a build that breaks because the scanner
    could not run has to look different from one that breaks because the code
    is vulnerable.
    """
    stderr.print(f"[red]error[/red] {message}")
    raise typer.Exit(code=int(code))


def fail_config(message: str) -> NoReturn:
    """Report a configuration problem and exit."""
    fail(message, code=ExitCode.CONFIG_ERROR)


__all__ = [
    "OutputFormat",
    "emit",
    "emit_json",
    "fail",
    "fail_config",
    "note",
    "stderr",
    "stdout",
    "warn",
]
