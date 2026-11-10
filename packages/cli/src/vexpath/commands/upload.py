"""``vexpath upload``: send a result document that already exists.

``vexpath scan --upload`` covers the ordinary case. This covers the one that
turns up in real pipelines: the scan ran in one job and the upload has to
happen in another, because the first job had no credential, or because the
result is an artefact several steps consume.

Re-running the scan to upload it would be the wrong answer. The analysis is
the expensive part and its result is a document; a second run against a
different advisory snapshot would not even produce the same verdicts, so what
got uploaded would not be what the earlier job reported.

The document is validated here, against the same model the analysis produced,
before anything is sent. A hand-edited or truncated artefact then fails with a
message about the file, rather than as a 422 from the platform describing a
field nobody chose.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from vexpath.commands import auth
from vexpath.output import OutputFormat, emit_json, fail, fail_config, note
from vexpath_core.models.results import ScanResults


def command(
    results: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            help="A document written by 'vexpath scan --format json'.",
        ),
    ],
    project: Annotated[
        str,
        typer.Option("--project", help="Slug of the project to upload to."),
    ],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Upload a scan result produced earlier.

    Validates the document before sending it, so a broken artefact is
    described in terms of the file rather than as a rejection from the server.
    """
    credential = auth.credential_or_exit()
    document = _load(results)
    stored = auth.upload_results(credential, project, document)

    if output_format is OutputFormat.JSON:
        emit_json(stored)
        return
    note(f"uploaded {results} to {credential.api_url} as scan {stored.get('id', 'unknown')}")


def _load(path: Path) -> dict[str, object]:
    """Read and validate the result document.

    Validated through ``ScanResults`` rather than merely parsed as JSON: the
    platform validates with the same model, so anything accepted here is
    accepted there, and the mismatch cannot show up as a confusing 422 after
    the upload has been attempted.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"{path} could not be read: {exc}")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail_config(
            f"{path} is not readable JSON: {exc}. It should be the output of "
            f"'vexpath scan --format json'."
        )

    if not isinstance(parsed, dict):
        fail_config(f"{path} holds {type(parsed).__name__}, not a scan result document.")

    try:
        ScanResults.model_validate(parsed)
    except ValidationError as exc:
        fields = ", ".join(
            ".".join(str(part) for part in error["loc"]) for error in exc.errors()[:5]
        )
        fail_config(
            f"{path} is not a scan result this build understands. Problem "
            f"fields: {fields or 'unknown'}. Re-run the scan with this version "
            f"of vexpath."
        )

    return parsed


__all__ = ["command"]
