"""The ``vexpath advisory`` command group: sync a corpus and inspect records."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

from vexpath import corpus
from vexpath.output import OutputFormat, emit, emit_json, fail, note
from vexpath.sources import SNAPSHOT_ENV
from vexpath_core.advisory.coverage import FixReferenceTier, measure
from vexpath_core.advisory.sync import DEFAULT_ECOSYSTEMS, AdvisorySyncError
from vexpath_core.advisory.sync import sync as run_sync
from vexpath_core.enums import canonical_ecosystem
from vexpath_core.snapshot import SnapshotIntegrityError, read_snapshot

app = typer.Typer(help="Download and inspect the advisory corpus.", no_args_is_help=True)


@app.command("pull")
def pull_corpus(
    directory: Annotated[
        Path | None,
        typer.Argument(
            help="Where to put it. Defaults to the per-user cache, where every command finds it."
        ),
    ] = None,
    url: Annotated[
        str | None,
        typer.Option("--url", help="Fetch from somewhere else: a fork, a mirror, your own build."),
    ] = None,
) -> None:
    """Download the published advisory corpus, with its vulnerable symbols.

    The corpus is what makes a finding clearable. OSV says a package is
    affected; it does not say which functions the fix changed, and without
    those there is nothing for a reachability search to look for -- so a scan
    with no corpus reports almost everything as ``symbols_unknown``, which is
    honest and useless.

    Building one means diffing the fix commit of every advisory, which is
    hours of cloning upstream repositories and produces the same answer for
    everybody. So it is built once and published, and this collects it.

    Verified on arrival: the content hash is recomputed over the records and
    checked against what the snapshot claims. A corpus that fails never
    replaces one that works.
    """
    try:
        destination, advisories, symbols = corpus.pull(directory, base_url=url)
    except corpus.CorpusError as exc:
        fail(str(exc))

    note(
        f"{advisories} advisories, {symbols} vulnerable symbols -> {destination}\n"
        f"Every command uses it from now on; override with --snapshot or "
        f"${SNAPSHOT_ENV}."
    )


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
            "or download one with 'vexpath advisory sync'."
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
    """Report what share of advisories reachability analysis could ever decide.

    Two different numbers, and conflating them would mislead:

    *Symbols* is the share of advisories that already name their vulnerable
    functions. Only Go advisories do. For PyPI this is zero and will stay zero,
    because OSV carries no such field for it.

    *Fix* is the share whose fix commit can be recovered, which is what symbol
    extraction needs. This is the ceiling on what reachability can ever speak
    to, and the number that decides whether the call-graph engine is worth
    building.
    """
    directory = snapshot or _snapshot_from_environment()
    if directory is None:
        fail(f"no snapshot given. Pass --snapshot or set ${SNAPSHOT_ENV}.")

    try:
        metadata, advisories = read_snapshot(directory)
    except FileNotFoundError as exc:
        fail(str(exc))
    except SnapshotIntegrityError as exc:
        fail(f"advisory snapshot is not trustworthy: {exc}")

    report = measure(advisories, snapshot_id=metadata.id)

    if output_format is OutputFormat.JSON:
        emit_json(
            {
                "snapshot": report.snapshot_id,
                "advisories": report.advisories,
                "withdrawn": report.withdrawn,
                "malicious": report.malicious,
                "ecosystems": [
                    {
                        "ecosystem": entry.ecosystem,
                        "advisories": entry.advisories,
                        "withdrawn": entry.withdrawn,
                        "malicious": entry.malicious,
                        "total_records": entry.total_records,
                        "with_symbols": entry.with_symbols,
                        "symbol_coverage": round(entry.symbol_coverage, 4),
                        "fix_reference_coverage": round(entry.fix_reference_coverage, 4),
                        "high_confidence_coverage": round(entry.high_confidence_coverage, 4),
                        "tiers": {
                            tier.value: entry.tiers.get(tier, 0) for tier in FixReferenceTier
                        },
                    }
                    for entry in report.ecosystems
                ],
            }
        )
        return

    lines = [
        f"Snapshot {report.snapshot_id}",
        "",
        f"{report.advisories} advisories that reachability analysis could apply to.",
        f"Excluded: {report.malicious} malicious-package records, {report.withdrawn} withdrawn.",
        "",
        f"{'ECOSYSTEM':<12} {'ANALYSABLE':>11} {'MALICIOUS':>10} {'SYMBOLS':>9} "
        f"{'FIX':>7} {'EXACT':>7}",
        "-" * 62,
    ]
    for entry in report.ecosystems:
        lines.append(
            f"{entry.ecosystem:<12} {entry.advisories:>11} {entry.malicious:>10} "
            f"{entry.symbol_coverage:>8.1%} "
            f"{entry.fix_reference_coverage:>6.1%} "
            f"{entry.high_confidence_coverage:>6.1%}"
        )

    lines.append("")
    lines.append("How a fix commit would be recovered")
    lines.append("")
    header = f"{'ECOSYSTEM':<12}" + "".join(f"{tier.value:>15}" for tier in FixReferenceTier)
    lines.append(header)
    lines.append("-" * len(header))
    for entry in report.ecosystems:
        row = f"{entry.ecosystem:<12}"
        for tier in FixReferenceTier:
            count = entry.tiers.get(tier, 0)
            share = count / entry.advisories if entry.advisories else 0.0
            row += f"{count:>8} {share:>5.0%} "
        lines.append(row.rstrip())

    lines.append("")
    lines.append(
        "ANALYSABLE excludes MALICIOUS records: malware has no fix to diff, and "
        "installing it runs it, so its presence alone is the finding."
    )
    lines.append(
        "SYMBOLS: advisories that already name their vulnerable functions. Only Go "
        "publishes these, and only in its own export."
    )
    lines.append(
        "FIX: advisories whose fix commit can be recovered, which is the ceiling "
        "on what reachability can decide."
    )
    lines.append("EXACT: of those, the ones resolving to a precise commit rather than a tag diff.")
    emit("\n".join(lines) + "\n")


def _snapshot_from_environment() -> Path | None:
    raw = os.environ.get(SNAPSHOT_ENV, "").strip()
    if not raw:
        return None
    candidate = Path(raw)
    return candidate if candidate.is_dir() else None


__all__ = ["app"]
