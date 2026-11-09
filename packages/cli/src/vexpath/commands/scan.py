"""The ``vexpath scan`` command: the default way the tool is used."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vexpath.exit_codes import ExitCode
from vexpath.output import OutputFormat, emit, emit_json, fail, note
from vexpath.sources import SNAPSHOT_ENV, advisory_source, close_source
from vexpath_core import report
from vexpath_core.advisory.source import AdvisorySourceError
from vexpath_core.enums import ComponentScope
from vexpath_core.sbom import LockfileError, UnknownSbomFormatError
from vexpath_core.sbom.cyclonedx import CycloneDxError
from vexpath_core.sbom.spdx import SpdxError
from vexpath_core.scan import ScanOptions, scanned_lockfile
from vexpath_core.scan import scan as run_scan


def command(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, help="Project directory to scan."),
    ] = Path(),
    sbom: Annotated[
        Path | None,
        typer.Option(
            "--sbom",
            exists=True,
            dir_okay=False,
            help="Analyse this SBOM instead of generating one from a lockfile.",
        ),
    ] = None,
    lockfile: Annotated[
        Path | None,
        typer.Option(
            "--lockfile",
            exists=True,
            dir_okay=False,
            help="Use this lockfile instead of searching the directory.",
        ),
    ] = None,
    snapshot: Annotated[
        Path | None,
        typer.Option(
            "--snapshot",
            exists=True,
            file_okay=False,
            help=(
                "Read advisories from this local snapshot, making the scan "
                f"reproducible and offline. Defaults to ${SNAPSHOT_ENV}."
            ),
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
    no_reach: Annotated[
        bool,
        typer.Option(
            "--no-reach",
            help="Skip reachability analysis and report matching only.",
        ),
    ] = False,
    ignore_dev: Annotated[
        bool,
        typer.Option(
            "--ignore-dev",
            help="Exclude development dependencies from analysis.",
        ),
    ] = False,
    show_cleared: Annotated[
        bool,
        typer.Option("--show-cleared", help="List findings that were cleared, too."),
    ] = False,
    entry_point: Annotated[
        str | None,
        typer.Option(
            "--entry-point",
            "-e",
            help=(
                "Comma-separated entry points to start the reachability search "
                "from, as module.path:function. Nothing beats being told how the "
                "application starts."
            ),
        ),
    ] = None,
    environment: Annotated[
        Path | None,
        typer.Option(
            "--environment",
            exists=True,
            file_okay=False,
            help=(
                "Virtual environment holding the installed dependencies. "
                "Defaults to the one this command is running in."
            ),
        ),
    ] = None,
    no_cache: Annotated[
        bool,
        typer.Option(
            "--no-cache", help="Rebuild dependency graphs instead of reusing cached ones."
        ),
    ] = False,
    fail_on_findings: Annotated[
        bool,
        typer.Option(
            "--fail-on-findings/--no-fail-on-findings",
            help=(
                "Exit with code 1 when anything needs attention. Until policy "
                "evaluation lands, this is the gate for CI."
            ),
        ),
    ] = False,
) -> None:
    """Scan a project for vulnerable dependencies.

    Reachability analysis runs by default and is what makes the report short:
    a finding is cleared only when the vulnerable code provably cannot run.
    Pass ``--no-reach`` to report matching alone, in which case nothing is
    cleared and the output says so.
    """
    if no_reach:
        note(
            "Reachability analysis is off, so this reports matching only. No "
            "finding will be cleared."
        )

    source = advisory_source(snapshot, result_noun="scan")
    scopes = (
        frozenset({ComponentScope.RUNTIME, ComponentScope.OPTIONAL})
        if ignore_dev
        else frozenset(ComponentScope)
    )
    options = ScanOptions(
        sbom_path=sbom,
        lockfile=lockfile,
        include_scopes=scopes,
        reachability=not no_reach,
        entry_points=tuple(
            entry.strip() for entry in (entry_point or "").split(",") if entry.strip()
        ),
        environment=environment,
        use_cache=not no_cache,
    )

    try:
        results = run_scan(path, source, options=options)
    except (LockfileError, UnknownSbomFormatError, CycloneDxError, SpdxError) as exc:
        fail(str(exc))
    except AdvisorySourceError as exc:
        fail(
            f"{exc}. To scan without network access, download a snapshot with "
            f"'vexpath advisory sync' and pass --snapshot."
        )
    finally:
        close_source(source)

    _render(results, output_format, path, options, show_cleared=show_cleared)

    needs_attention = len(results.findings_needing_attention())
    if fail_on_findings and needs_attention:
        raise typer.Exit(code=int(ExitCode.POLICY_FAILED))


def _render(
    results: object,
    output_format: OutputFormat,
    path: Path,
    options: ScanOptions,
    *,
    show_cleared: bool,
) -> None:
    from vexpath_core.models.results import ScanResults

    assert isinstance(results, ScanResults)  # narrowed for the type checker

    if output_format is OutputFormat.JSON:
        emit_json(results.model_dump(mode="json", by_alias=True))
        return
    if output_format is OutputFormat.SARIF:
        emit(report.render_sarif_json(results, lockfile_path=scanned_lockfile(path, options)))
        return
    if output_format is OutputFormat.MARKDOWN:
        emit(report.render_markdown(results, show_cleared=show_cleared))
        return
    emit(report.render_text(results, show_cleared=show_cleared))


__all__ = ["SNAPSHOT_ENV", "command"]
