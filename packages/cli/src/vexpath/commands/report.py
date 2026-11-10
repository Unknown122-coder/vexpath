"""``vexpath report``: render a scan that already ran, in another format.

The analysis is the expensive part. A cold scan of a real project takes minutes
because it downloads and parses every dependency's source; the result is a
document. Re-running it to get the same conclusions as SARIF rather than as a
table is pure waste, and worse than waste: a second run against a corpus that
has moved on produces *different* verdicts, so the SARIF a pipeline uploads
would not match the table a developer read.

So this reads the document and re-renders it. Nothing is re-analysed, nothing
can disagree. It exists because the GitHub Action needs the same scan three
ways -- a table in the log, markdown in the step summary, SARIF for code
scanning -- and three scans would be three answers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vexpath.output import OutputFormat, emit, fail, note
from vexpath_core import report as renderers
from vexpath_core.models.results import ScanResults


def command(
    results_file: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            help="A document written by 'vexpath scan --format json'.",
        ),
    ],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            dir_okay=False,
            help="Write here instead of to standard output.",
        ),
    ] = None,
    show_cleared: Annotated[
        bool,
        typer.Option("--show-cleared", help="List findings that were cleared, too."),
    ] = False,
    summary: Annotated[
        bool,
        typer.Option(
            "--summary",
            help=(
                "Print the counts as key=value lines instead of a report, for "
                "a CI step to read. The counts are computed by the same code "
                "that renders every other format, so a workflow cannot "
                "disagree with the report beside it."
            ),
        ),
    ] = False,
    lockfile: Annotated[
        str | None,
        typer.Option(
            "--lockfile",
            help=(
                "Path to record as the location of each SARIF result. Code "
                "scanning anchors an alert to a file, and a lockfile is the "
                "file a dependency finding is actually about."
            ),
        ),
    ] = None,
) -> None:
    """Re-render a scan result without re-running the analysis.

    Exits 2 if the document is not one this build understands. It is validated
    through the same model the analysis produced, so a hand-edited file is
    refused here rather than rendering into a report that looks authoritative.
    """
    try:
        results = ScanResults.model_validate_json(results_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"{results_file} is not a vexpath scan result: {exc}")

    if summary:
        emit(_summary(results))
        return

    rendered = _render(
        results,
        output_format,
        show_cleared=show_cleared,
        lockfile=lockfile or _lockfile_of(results),
    )

    if output is None:
        emit(rendered)
        return

    try:
        output.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        fail(f"{output} could not be written: {exc}")
    # To standard error, so a caller redirecting standard output into a file
    # does not find this line in it.
    note(f"wrote {output}")


def _render(
    results: ScanResults,
    output_format: OutputFormat,
    *,
    show_cleared: bool,
    lockfile: str,
) -> str:
    if output_format is OutputFormat.JSON:
        # Re-serialised through the model rather than copied byte for byte: a
        # document that round-trips is one this build genuinely understood.
        import json

        return json.dumps(results.model_dump(mode="json", by_alias=True), indent=2)
    if output_format is OutputFormat.SARIF:
        return renderers.render_sarif_json(results, lockfile_path=lockfile)
    if output_format is OutputFormat.MARKDOWN:
        return renderers.render_markdown(results, show_cleared=show_cleared)
    return renderers.render_text(results, show_cleared=show_cleared)


def _summary(results: ScanResults) -> str:
    """The counts a CI step needs, as ``key=value`` lines.

    This shape so a GitHub Actions step can append it straight to
    ``$GITHUB_OUTPUT``, and any other shell can ``eval`` it. Computed here
    rather than in YAML by whoever writes the workflow: the definitions of
    "needs attention" and "reachable" are decisions this project has already
    made, and a second implementation in a shell script would eventually
    disagree with the report printed beside it.
    """
    from vexpath_core.enums import Verdict

    by_verdict = results.counts_by_verdict()
    lines = [
        f"total={len(results.findings)}",
        f"needs_attention={len(results.findings_needing_attention())}",
        f"cleared={by_verdict[Verdict.NOT_AFFECTED]}",
        f"reachable={len(results.reachable_findings())}",
        f"under_investigation={by_verdict[Verdict.UNDER_INVESTIGATION]}",
        # Empty rather than "true" when no policy ran: a workflow must be able
        # to tell "the gate passed" from "there was no gate".
        f"policy_passed={'' if results.policy is None else str(results.policy.passed).lower()}",
        f"reproducible={str(results.is_reproducible).lower()}",
        # Whether reachability ran at all. A cleared count means nothing
        # without it: zero cleared because everything is reachable is a
        # different situation from zero cleared because nobody looked.
        f"reachability_analysed={str(_analysed(results)).lower()}",
    ]
    return "\n".join(lines) + "\n"


def _analysed(results: ScanResults) -> bool:
    """Whether the reachability search ran at all.

    True when the scan recorded the entry points it started from, or when any
    finding carries a reachability result. Derived rather than stored, because
    the document already says both of those things and a third field could
    contradict them.
    """
    if results.entry_points is not None:
        return True
    return any(finding.reach is not None for finding in results.findings)


def _lockfile_of(results: ScanResults) -> str:
    """What the scan said it read, for the SARIF location.

    Taken from the document rather than guessed from the working directory,
    because this command may run in a different checkout from the scan -- a
    release job rendering a scan an earlier job produced, for instance. A
    document written by an older build carries no such field, which is why
    ``--lockfile`` exists and why "unknown" is the last resort rather than an
    error.
    """
    return results.project.lockfile or "unknown"


__all__ = ["command"]
