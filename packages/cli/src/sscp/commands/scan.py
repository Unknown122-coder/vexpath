"""The ``sscp scan`` command: the default way the tool is used."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

from sscp.exit_codes import ExitCode
from sscp.output import OutputFormat, emit, emit_json, fail, note, warn
from sscp_core import report
from sscp_core.advisory import OsvApiSource, SnapshotSource
from sscp_core.advisory.source import AdvisorySourceError
from sscp_core.enums import ComponentScope
from sscp_core.protocols import AdvisorySource
from sscp_core.sbom import LockfileError, UnknownSbomFormatError
from sscp_core.sbom.cyclonedx import CycloneDxError
from sscp_core.sbom.spdx import SpdxError
from sscp_core.scan import ScanOptions, scanned_lockfile
from sscp_core.scan import scan as run_scan
from sscp_core.snapshot import SnapshotIntegrityError

#: Environment variable naming a local advisory snapshot. Set it and scans
#: become reproducible and offline by default.
SNAPSHOT_ENV = "SSCP_ADVISORY_SNAPSHOT_DIR"
OSV_BASE_ENV = "SSCP_OSV_API_BASE"


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

    Reachability analysis is not implemented yet, so every scan currently
    behaves as ``--no-reach``: findings are reported as affected or under
    investigation, and nothing is ever cleared. That is the honest state of the
    tool rather than a silent limitation.
    """
    if not no_reach:
        # Saying this plainly beats letting someone believe a verdict was
        # reachability-informed when it was not.
        note(
            "Reachability analysis is not available in this build, so this scan "
            "reports matching only. No finding will be cleared."
        )

    source = _advisory_source(snapshot)
    scopes = (
        frozenset({ComponentScope.RUNTIME, ComponentScope.OPTIONAL})
        if ignore_dev
        else frozenset(ComponentScope)
    )
    options = ScanOptions(sbom_path=sbom, lockfile=lockfile, include_scopes=scopes)

    try:
        results = run_scan(path, source, options=options)
    except (LockfileError, UnknownSbomFormatError, CycloneDxError, SpdxError) as exc:
        fail(str(exc))
    except AdvisorySourceError as exc:
        fail(
            f"{exc}. To scan without network access, download a snapshot with "
            f"'sscp advisory sync' and pass --snapshot."
        )
    finally:
        close = getattr(source, "close", None)
        if callable(close):
            close()

    _render(results, output_format, path, options, show_cleared=show_cleared)

    needs_attention = len(results.findings_needing_attention())
    if fail_on_findings and needs_attention:
        raise typer.Exit(code=int(ExitCode.POLICY_FAILED))


def _advisory_source(snapshot: Path | None) -> AdvisorySource:
    """Choose where advisories come from, preferring a reproducible snapshot."""
    directory = snapshot or _snapshot_from_environment()
    if directory is not None:
        try:
            source = SnapshotSource(directory)
        except FileNotFoundError as exc:
            fail(str(exc))
        except SnapshotIntegrityError as exc:
            # A corrupted corpus changes verdicts, so this is fatal.
            fail(f"advisory snapshot is not trustworthy: {exc}")
        note(f"using advisory snapshot {source.snapshot_id} from {directory}")
        return source

    warn(
        "No advisory snapshot was given, so advisories will be read live from "
        "OSV and this scan will not be reproducible. Run 'sscp advisory sync' "
        f"and set ${SNAPSHOT_ENV} to fix that."
    )
    return OsvApiSource(base_url=os.environ.get(OSV_BASE_ENV, "https://api.osv.dev"))


def _snapshot_from_environment() -> Path | None:
    raw = os.environ.get(SNAPSHOT_ENV, "").strip()
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_dir():
        warn(f"${SNAPSHOT_ENV} points at {candidate}, which is not a directory; ignoring it.")
        return None
    return candidate


def _render(
    results: object,
    output_format: OutputFormat,
    path: Path,
    options: ScanOptions,
    *,
    show_cleared: bool,
) -> None:
    from sscp_core.models.results import ScanResults

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
