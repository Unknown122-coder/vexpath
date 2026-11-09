"""The ``sscp advisory`` command group: sync a corpus and inspect records."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

from sscp.output import OutputFormat, emit, emit_json, fail, note
from sscp_core.advisory.sync import DEFAULT_ECOSYSTEMS, AdvisorySyncError
from sscp_core.advisory.sync import sync as run_sync
from sscp_core.enums import canonical_ecosystem
from sscp_core.snapshot import SnapshotIntegrityError, read_snapshot

SNAPSHOT_ENV = "SSCP_ADVISORY_SNAPSHOT_DIR"

app = typer.Typer(help="Download and inspect the advisory corpus.", no_args_is_help=True)


@app.command("sync")
def sync(
    directory: Annotated[
        Path,
        typer.Argument(help="Where to write the snapshot."),
    ] = Path("advisories"),
    ecosystems: Annotated[
        str,
        typer.Option(
            "--ecosystem",
            "-e",
            help="Comma-separated OSV ecosystem names to download.",
        ),
    ] = ",".join(DEFAULT_ECOSYSTEMS),
) -> None:
    """Download advisories and write a local snapshot.

    A snapshot makes scans reproducible and lets them run with no network
    access at all, which is what an air-gapped environment needs and what makes
    a verdict auditable months later.
    """
    names = [canonical_ecosystem(name) for name in ecosystems.split(",") if name.strip()]
    if not names:
        fail("no ecosystems given; pass --ecosystem PyPI for example")

    note(f"downloading {', '.join(names)} from OSV; this takes a few minutes")
    try:
        report = run_sync(directory, ecosystems=names)
    except AdvisorySyncError as exc:
        fail(str(exc))

    lines = [
        f"Wrote snapshot {report.snapshot.id} to {directory}",
        f"  advisories {report.advisories}",
    ]
    for ecosystem, share in sorted(report.symbol_coverage.items()):
        counts = report.snapshot.counts.get(ecosystem, {})
        lines.append(
            f"  {ecosystem:<10} {counts.get('advisories', 0):>6} advisories, "
            f"{counts.get('with_symbols', 0):>6} with vulnerable symbols ({share:.1%})"
        )
    if report.skipped:
        lines.append(f"  skipped    {len(report.skipped)} malformed record(s)")
    lines.append("")
    lines.append(f"Set {SNAPSHOT_ENV}={directory} so scans use it by default.")
    emit("\n".join(lines) + "\n")


@app.command("show")
def show(
    advisory_id: Annotated[
        str, typer.Argument(help="Advisory identifier, such as CVE-2024-35195.")
    ],
    snapshot: Annotated[
        Path | None,
        typer.Option(
            "--snapshot",
            exists=True,
            file_okay=False,
            help=f"Snapshot directory to read. Defaults to ${SNAPSHOT_ENV}.",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Show one advisory: affected ranges, severity and vulnerable symbols.

    The vulnerable symbols are what reachability analysis searches for, so this
    is the command for understanding why a finding was or was not reachable.
    """
    directory = snapshot or _snapshot_from_environment()
    if directory is None:
        fail(
            f"no snapshot given. Pass --snapshot, or set ${SNAPSHOT_ENV}, "
            "or download one with 'sscp advisory sync'."
        )

    try:
        _, advisories = read_snapshot(directory)
    except FileNotFoundError as exc:
        fail(str(exc))
    except SnapshotIntegrityError as exc:
        fail(f"advisory snapshot is not trustworthy: {exc}")

    wanted = advisory_id.strip().upper()
    found = next(
        (
            advisory
            for advisory in advisories
            if any(identifier.upper() == wanted for identifier in advisory.all_ids)
        ),
        None,
    )
    if found is None:
        fail(f"{advisory_id} is not in the snapshot at {directory}")

    if output_format is OutputFormat.JSON:
        emit_json(found.model_dump(mode="json"))
        return

    lines = [f"{found.id}  {found.severity.value}"]
    if found.aliases:
        lines.append(f"  also known as   {', '.join(found.aliases)}")
    if found.summary:
        lines.append(f"  summary         {found.summary}")
    if found.cvss_v3:
        lines.append(f"  CVSS v3         {found.cvss_v3.base_score}  {found.cvss_v3.vector}")
    if found.cvss_v4:
        lines.append(f"  CVSS v4         {found.cvss_v4.vector}")
    if found.epss_score is not None:
        lines.append(f"  EPSS            {found.epss_score:.5f}")
    if found.kev:
        lines.append("  CISA KEV        yes, known to be exploited")
    if found.cwe_ids:
        lines.append(f"  weaknesses      {', '.join(found.cwe_ids)}")
    if found.repo_url:
        lines.append(f"  repository      {found.repo_url}")
    if found.is_withdrawn:
        lines.append("  withdrawn       yes, this advisory produces no findings")

    lines.append("")
    lines.append("Affected packages")
    for package in found.affected:
        lines.append(f"  {package.ecosystem} {package.name}")
        for affected_range in package.ranges:
            events = " ".join(
                f"{field}={value}"
                for event in affected_range.events
                for field, value in event.model_dump(exclude_none=True).items()
            )
            lines.append(f"    {affected_range.type.value}: {events}")
        if package.versions:
            shown = ", ".join(package.versions[:8])
            more = "" if len(package.versions) <= 8 else f" and {len(package.versions) - 8} more"
            lines.append(f"    explicit versions: {shown}{more}")
        if package.fixed_versions:
            lines.append(f"    fixed in: {', '.join(package.fixed_versions)}")

    lines.append("")
    if found.symbols:
        lines.append(f"Vulnerable symbols ({found.symbols_status.value})")
        for symbol in found.symbols:
            lines.append(
                f"  {symbol.symbol}  [{symbol.kind.value}, {symbol.source.value}, "
                f"{symbol.confidence.value} confidence]"
            )
    else:
        lines.append(
            f"No vulnerable symbols ({found.symbols_status.value}), so reachability "
            "cannot be determined for this advisory and findings stay under "
            "investigation."
        )

    emit("\n".join(lines) + "\n")


@app.command("coverage")
def coverage(
    snapshot: Annotated[
        Path | None,
        typer.Option(
            "--snapshot",
            exists=True,
            file_okay=False,
            help=f"Snapshot directory to read. Defaults to ${SNAPSHOT_ENV}.",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Report what share of advisories carry vulnerable symbols.

    This is the measurement the product's usefulness rests on: reachability can
    only be decided for an advisory whose vulnerable symbols are known. A low
    number here caps how much of the noise the tool can ever remove.
    """
    directory = snapshot or _snapshot_from_environment()
    if directory is None:
        fail(f"no snapshot given. Pass --snapshot or set ${SNAPSHOT_ENV}.")

    try:
        metadata, _ = read_snapshot(directory)
    except FileNotFoundError as exc:
        fail(str(exc))
    except SnapshotIntegrityError as exc:
        fail(f"advisory snapshot is not trustworthy: {exc}")

    rows = []
    for ecosystem in sorted(metadata.counts):
        counts = metadata.counts[ecosystem]
        total = counts.get("advisories", 0)
        with_symbols = counts.get("with_symbols", 0)
        rows.append(
            {
                "ecosystem": ecosystem,
                "advisories": total,
                "with_symbols": with_symbols,
                "coverage": (with_symbols / total) if total else 0.0,
            }
        )

    if output_format is OutputFormat.JSON:
        emit_json({"snapshot": metadata.id, "ecosystems": rows})
        return

    lines = [
        f"Snapshot {metadata.id}",
        "",
        f"{'ECOSYSTEM':<12} {'ADVISORIES':>11} {'WITH SYMBOLS':>13} {'COVERAGE':>9}",
        "-" * 48,
    ]
    for row in rows:
        lines.append(
            f"{row['ecosystem']:<12} {row['advisories']:>11} "
            f"{row['with_symbols']:>13} {row['coverage']:>8.1%}"
        )
    emit("\n".join(lines) + "\n")


def _snapshot_from_environment() -> Path | None:
    raw = os.environ.get(SNAPSHOT_ENV, "").strip()
    if not raw:
        return None
    candidate = Path(raw)
    return candidate if candidate.is_dir() else None


__all__ = ["app"]
