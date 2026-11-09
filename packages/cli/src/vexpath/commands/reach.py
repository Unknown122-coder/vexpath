"""The ``vexpath reach`` command: explain one advisory against one project.

``vexpath scan`` says what to act on. This says why, for a single advisory,
with every piece of evidence the verdict rests on. It is the command someone
runs when they disagree with the scan, which is exactly when a security tool
has to be able to show its work.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vexpath.exit_codes import ExitCode
from vexpath.output import OutputFormat, emit, emit_json, fail
from vexpath.sources import SNAPSHOT_ENV, advisory_source, close_source
from vexpath_core import report
from vexpath_core.advisory.source import AdvisorySourceError
from vexpath_core.enums import Verdict
from vexpath_core.sbom import LockfileError, UnknownSbomFormatError
from vexpath_core.sbom.cyclonedx import CycloneDxError
from vexpath_core.sbom.spdx import SpdxError
from vexpath_core.scan import ScanOptions
from vexpath_core.triage import TriageError, triage


def command(
    advisory: Annotated[
        str,
        typer.Option(
            "--advisory",
            "-a",
            help="The advisory to explain. Any of its identifiers works.",
        ),
    ],
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, help="Project directory to analyse."),
    ] = Path(),
    symbol: Annotated[
        str | None,
        typer.Option(
            "--symbol",
            "-s",
            help=(
                "Comma-separated symbols to search for in addition to the "
                "advisory's own, as module.path:function or a dotted name. "
                "Useful when an advisory carries no fix commit. Recorded as "
                "manually supplied, which caps the report's confidence."
            ),
        ),
    ] = None,
    snapshot: Annotated[
        Path | None,
        typer.Option(
            "--snapshot",
            exists=True,
            file_okay=False,
            help=(f"Read advisories from this local snapshot. Defaults to ${SNAPSHOT_ENV}."),
        ),
    ] = None,
    entry_point: Annotated[
        str | None,
        typer.Option(
            "--entry-point",
            "-e",
            help=(
                "Comma-separated entry points to start from, as "
                "module.path:function. Nothing beats being told how the "
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
    lockfile: Annotated[
        Path | None,
        typer.Option(
            "--lockfile",
            exists=True,
            dir_okay=False,
            help="Use this lockfile instead of searching the directory.",
        ),
    ] = None,
    no_cache: Annotated[
        bool,
        typer.Option("--no-cache", help="Rebuild dependency graphs instead of reusing them."),
    ] = False,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Explain one advisory's reachability verdict for this project.

    Prints the symbols searched for and where they came from, which of them
    exist in the installed version, which entry points reach them with the
    call path for each, and the graph the answer rests on.
    """
    source = advisory_source(snapshot, result_noun="explanation")
    options = ScanOptions(
        lockfile=lockfile,
        entry_points=_split(entry_point),
        environment=environment,
        use_cache=not no_cache,
    )

    try:
        result = triage(
            path,
            advisory,
            source,
            options=options,
            extra_symbols=_split(symbol),
        )
    except TriageError as exc:
        fail(str(exc))
    except (LockfileError, UnknownSbomFormatError, CycloneDxError, SpdxError) as exc:
        fail(str(exc))
    except AdvisorySourceError as exc:
        fail(
            f"{exc}. To work without network access, download a snapshot with "
            f"'vexpath advisory sync' and pass --snapshot."
        )
    finally:
        close_source(source)

    if output_format is OutputFormat.JSON:
        emit_json(_payload(result))
    else:
        emit(report.render_triage(result))

    # A reachable verdict is the one a caller may want to act on, so it is
    # distinguishable without parsing the output. An admitted unknown is not an
    # analysis failure, so it stays at zero.
    if result.verdict is Verdict.AFFECTED:
        raise typer.Exit(code=int(ExitCode.POLICY_FAILED))


def _split(raw: str | None) -> tuple[str, ...]:
    return tuple(entry.strip() for entry in (raw or "").split(",") if entry.strip())


def _payload(result: object) -> dict[str, object]:
    """Serialise a triage report.

    Written out by hand rather than dumped from the dataclass, because this is
    a contract with whatever consumes it and should not change shape every time
    an internal field is renamed.
    """
    from vexpath_core.triage import TriageReport

    assert isinstance(result, TriageReport)  # narrowed for the type checker
    reach = result.reach
    return {
        "advisory": {
            "id": result.advisory_id,
            "summary": result.summary,
            "severity": result.severity.value,
            "aliases": list(result.aliases),
        },
        "component": {
            "purl": result.component.purl,
            "ecosystem": result.component.ecosystem,
            "name": result.component.name,
            "version": result.component.version,
            "direct": result.component.direct,
        },
        "version_affected": result.version_affected,
        "verdict": result.verdict.value,
        "advisory_snapshot_id": result.snapshot_id,
        "reproducible": result.is_reproducible,
        "reach": reach.model_dump(mode="json") if reach is not None else None,
        "symbols": [
            {
                "symbol": probe.symbol,
                "kind": probe.kind.value,
                "source": probe.source.value,
                "confidence": probe.confidence.value,
                "defined": probe.defined,
                "referenced": probe.referenced,
                "status": probe.status,
            }
            for probe in result.symbols
        ],
        "entry_points": {
            "source": result.entry_point_source.value,
            "count": result.entry_point_count,
            "examined": [
                {
                    "entry_point": entry.entry_point,
                    "status": entry.status,
                    "symbol": entry.symbol,
                    "path": [
                        {
                            "symbol": step.symbol,
                            "file": step.file,
                            "line": step.line,
                            "edge_kind": step.edge_kind.value,
                        }
                        for step in entry.path
                    ],
                }
                for entry in result.entry_points
            ],
        },
        "graph": result.graph.model_dump(mode="json") if result.graph is not None else None,
        "notes": list(result.notes),
    }


__all__ = ["command"]
