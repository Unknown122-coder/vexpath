"""The ``vexpath vex`` command group: publish the analysis as OpenVEX.

A scan's verdicts are an opinion until they are in a form someone else's tools
read. This is that form.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from vexpath.exit_codes import ExitCode
from vexpath.output import emit, fail, note
from vexpath.sources import advisory_source, close_source
from vexpath_core import vex
from vexpath_core.advisory.source import AdvisorySourceError
from vexpath_core.enums import ComponentScope
from vexpath_core.models.results import ScanResults
from vexpath_core.sbom import LockfileError, UnknownSbomFormatError
from vexpath_core.sbom.cyclonedx import CycloneDxError
from vexpath_core.sbom.spdx import SpdxError
from vexpath_core.scan import ScanOptions
from vexpath_core.scan import scan as run_scan

app = typer.Typer(help="Publish scan conclusions as VEX.", no_args_is_help=True)


@app.command("export")
def export(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, help="Project directory to scan."),
    ] = Path(),
    author: Annotated[
        str | None,
        typer.Option(
            "--author",
            "-a",
            help=(
                "Who is making these statements, as an organisation or a person. "
                "Required: a VEX document nobody can attribute is one nobody can "
                "decide whether to believe."
            ),
        ),
    ] = None,
    product: Annotated[
        str | None,
        typer.Option(
            "--product",
            "-p",
            help=(
                "Identifier of the product these statements are about, ideally a "
                "purl. Defaults to the project slug. This is your product, not "
                "the vulnerable dependency: the dependency is recorded as a "
                "subcomponent."
            ),
        ),
    ] = None,
    results_file: Annotated[
        Path | None,
        typer.Option(
            "--results",
            exists=True,
            dir_okay=False,
            help=(
                "Use the JSON output of an earlier scan instead of scanning "
                "again. The verdicts are the scan's, so re-deriving them would "
                "risk a document that disagrees with the report it came from."
            ),
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", dir_okay=False, help="Write here instead of stdout."),
    ] = None,
    snapshot: Annotated[
        Path | None,
        typer.Option("--snapshot", exists=True, file_okay=False, help="Advisory snapshot to use."),
    ] = None,
    environment: Annotated[
        Path | None,
        typer.Option(
            "--environment",
            exists=True,
            file_okay=False,
            help="Virtual environment holding the installed dependencies.",
        ),
    ] = None,
    download_missing: Annotated[
        bool,
        typer.Option(
            "--download-missing",
            help="Fetch a dependency's source from the index when it is not installed.",
        ),
    ] = False,
    document_version: Annotated[
        int,
        typer.Option(
            "--document-version",
            min=1,
            help=(
                "Version of this document for this product. Increment it when "
                "publishing a document that supersedes an earlier one."
            ),
        ),
    ] = 1,
    skip_open: Annotated[
        bool,
        typer.Option(
            "--skip-under-investigation",
            help=(
                "Leave out findings still being analysed. Off by default: the "
                "absence of a statement reads as 'not an issue', and that is not "
                "what under investigation means."
            ),
        ),
    ] = False,
    ignore_dev: Annotated[
        bool,
        typer.Option("--ignore-dev", help="Exclude development dependencies."),
    ] = False,
) -> None:
    """Write an OpenVEX 0.2.0 document for this project.

    The document states, for every advisory that matches a dependency, whether
    the vulnerable code can run in your product, with the evidence for each
    answer. A finding is stated as not affected only where reachability proved
    the code is not in the execute path, which is the one justification this
    analysis earns.

    Byte-identical for identical results, so the document can be diffed between
    scans and its hash is worth attesting.
    """
    if author is None or not author.strip():
        fail(
            "--author is required. A VEX document is believed on the strength of "
            "who stands behind it, so it cannot be published anonymously."
        )

    results = (
        _load_results(results_file)
        if results_file is not None
        else _scan(
            path, snapshot, environment, download_missing=download_missing, ignore_dev=ignore_dev
        )
    )

    try:
        rendered = vex.render_json(
            results,
            vex.VexIdentity(author=author.strip(), product_id=product),
            version=document_version,
            include_under_investigation=not skip_open,
        )
    except vex.VexError as exc:
        fail(str(exc))

    document = json.loads(rendered)
    counts = vex.statement_counts(document)
    note(
        f"{len(document['statements'])} statement(s): "
        + ", ".join(f"{count} {status}" for status, count in counts.items())
    )
    note(f"document {document['@id']}")
    note(f"sha256 {vex.document_sha256(rendered)}")

    if output is None:
        emit(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8", newline="\n")
    note(f"written to {output}")


def _load_results(path: Path) -> ScanResults:
    try:
        return ScanResults.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"{path} is not a vexpath scan result: {exc}")
        raise  # unreachable; fail exits


def _scan(
    path: Path,
    snapshot: Path | None,
    environment: Path | None,
    *,
    download_missing: bool,
    ignore_dev: bool,
) -> ScanResults:
    source = advisory_source(snapshot, result_noun="VEX document")
    scopes = (
        frozenset({ComponentScope.RUNTIME, ComponentScope.OPTIONAL})
        if ignore_dev
        else frozenset(ComponentScope)
    )
    options = ScanOptions(
        include_scopes=scopes,
        environment=environment,
        download_missing=download_missing,
    )
    try:
        return run_scan(path, source, options=options)
    except (LockfileError, UnknownSbomFormatError, CycloneDxError, SpdxError) as exc:
        fail(str(exc))
    except AdvisorySourceError as exc:
        fail(f"{exc}. Download a snapshot with 'vexpath advisory sync' and pass --snapshot.")
    finally:
        close_source(source)
    raise typer.Exit(code=int(ExitCode.ANALYSIS_ERROR))  # unreachable


__all__ = ["app"]
