"""Write the database's advisory corpus back out as a snapshot.

This closes the loop. `sync-advisories` downloads a corpus that carries no
vulnerable symbols, because OSV does not publish them. `extract-symbols` reads
each advisory's fix commit and fills them in, but it writes to the database,
and the command-line tool reads a snapshot directory. Without this step the
symbols that make reachability work never reach the tool that does the
reaching.

So the sequence a deployment runs is: sync, extract, export, publish. What it
publishes is a corpus with symbols in it, which is the thing a scan needs and
the thing nobody else distributes.

The snapshot written here is identical in shape to one written by a download,
including its content hash, so everything that reads a snapshot reads this one
without knowing the difference.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, Select, select

from vexpath_core.enums import Severity, SymbolsStatus
from vexpath_core.ids import new_ulid
from vexpath_core.models.advisory import Advisory, AdvisorySnapshot
from vexpath_core.snapshot import write_snapshot
from vexpath_db.tables import advisories, advisory_affected, vulnerable_symbols
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

#: Rows read per round trip. The whole corpus is tens of thousands of
#: advisories with their ranges and symbols, which is more than belongs in
#: memory at once on a small worker.
PAGE = 2000


@dataclass(frozen=True, slots=True)
class ExportReport:
    """What an export wrote."""

    snapshot_id: str
    directory: Path
    advisories: int
    symbols: int
    with_symbols: int
    content_sha256: str

    @property
    def symbol_coverage(self) -> float:
        return self.with_symbols / self.advisories if self.advisories else 0.0

    def summary_line(self) -> str:
        return (
            f"snapshot {self.snapshot_id}: {self.advisories} advisories, "
            f"{self.symbols} symbols across {self.with_symbols} advisories "
            f"({self.symbol_coverage:.1%} symbol coverage) -> {self.directory}"
        )


def export_snapshot(
    engine: Engine,
    directory: Path,
    *,
    ecosystems: Sequence[str] | None = None,
    only_with_symbols: bool = False,
) -> ExportReport:
    """Write the corpus in the database to ``directory`` as a snapshot.

    Args:
        engine: Database holding the corpus.
        directory: Where to write ``snapshot.json`` and ``advisories.jsonl``.
        ecosystems: Restrict to advisories affecting these ecosystems. Omitted
            means every ecosystem in the database.
        only_with_symbols: Write only advisories that have vulnerable symbols.
            Useful for a small artefact when the consumer already has a corpus
            and wants the symbols; not a substitute for the full one, because
            an advisory missing from a snapshot produces no finding at all
            rather than an unresolved one.

    Returns:
        What was written, including the content hash a scan records.
    """
    log.info("advisory.export.start", directory=str(directory))

    rows = _advisory_rows(engine, ecosystems)
    symbols_by_advisory = _symbols(engine, ecosystems)
    affected_by_advisory = _affected(engine, ecosystems)

    records: list[Advisory] = []
    symbol_count = 0
    with_symbols = 0
    for row in rows:
        identifier = str(row["id"])
        symbols = symbols_by_advisory.get(identifier, [])
        affected = affected_by_advisory.get(identifier, [])
        if only_with_symbols and not symbols:
            continue
        if not affected:
            # An advisory with no affected package can never match a component,
            # so writing it would only grow the file.
            continue
        records.append(_advisory(row, affected, symbols))
        symbol_count += len(symbols)
        with_symbols += 1 if symbols else 0

    stored = write_snapshot(
        directory,
        AdvisorySnapshot(
            id=new_ulid(),
            created_at=datetime.now(UTC),
            content_sha256="0" * 64,
            ecosystems=(),
        ),
        records,
    )

    report = ExportReport(
        snapshot_id=stored.id,
        directory=directory,
        advisories=len(records),
        symbols=symbol_count,
        with_symbols=with_symbols,
        content_sha256=stored.content_sha256,
    )
    log.info("advisory.export.done", summary=report.summary_line())
    return report


def _in_ecosystems(statement: Select, ecosystems: Sequence[str] | None) -> Select:  # type: ignore[type-arg]
    """Narrow a query to advisories affecting the given ecosystems."""
    if not ecosystems:
        return statement
    matching = select(advisory_affected.c.advisory_id).where(
        advisory_affected.c.ecosystem.in_(list(ecosystems))
    )
    return statement.where(advisories.c.id.in_(matching))


def _advisory_rows(engine: Engine, ecosystems: Sequence[str] | None) -> list[dict[str, object]]:
    statement = _in_ecosystems(select(advisories), ecosystems).order_by(advisories.c.id.asc())
    with engine.connect().execution_options(stream_results=True) as connection:
        return [dict(row) for row in connection.execute(statement).mappings()]


def _symbols(
    engine: Engine, ecosystems: Sequence[str] | None
) -> dict[str, list[dict[str, object]]]:
    statement = select(vulnerable_symbols).order_by(
        vulnerable_symbols.c.advisory_id.asc(), vulnerable_symbols.c.symbol.asc()
    )
    if ecosystems:
        statement = statement.where(vulnerable_symbols.c.ecosystem.in_(list(ecosystems)))

    grouped: dict[str, list[dict[str, object]]] = {}
    with engine.connect().execution_options(stream_results=True) as connection:
        for row in connection.execute(statement).mappings():
            grouped.setdefault(str(row["advisory_id"]), []).append(dict(row))
    return grouped


def _affected(
    engine: Engine, ecosystems: Sequence[str] | None
) -> dict[str, list[dict[str, object]]]:
    statement = select(advisory_affected).order_by(
        advisory_affected.c.advisory_id.asc(), advisory_affected.c.package_name.asc()
    )
    if ecosystems:
        statement = statement.where(advisory_affected.c.ecosystem.in_(list(ecosystems)))

    grouped: dict[str, list[dict[str, object]]] = {}
    with engine.connect().execution_options(stream_results=True) as connection:
        for row in connection.execute(statement).mappings():
            grouped.setdefault(str(row["advisory_id"]), []).append(dict(row))
    return grouped


def _advisory(
    row: dict[str, object],
    affected: list[dict[str, object]],
    symbols: list[dict[str, object]],
) -> Advisory:
    """Rebuild one advisory from its rows.

    Validated through the model rather than assembled as a dict, so the same
    invariants a downloaded advisory passes apply to an exported one: one entry
    per affected package, and no malicious-package record left waiting for
    symbols.
    """
    status = row.get("symbols_status") or SymbolsStatus.PENDING
    return Advisory.model_validate(
        {
            "id": row["id"],
            "aliases": row.get("aliases") or (),
            "summary": row.get("summary") or "",
            "details": row.get("details") or "",
            "severity": row.get("severity") or Severity.UNKNOWN,
            "cvss_v3": row.get("cvss_v3"),
            "cvss_v4": row.get("cvss_v4"),
            "epss_score": row.get("epss_score"),
            "epss_percentile": row.get("epss_percentile"),
            "kev": bool(row.get("kev")),
            "kev_added_at": row.get("kev_added_at"),
            "cwe_ids": row.get("cwe_ids") or (),
            "references": row.get("references") or (),
            "repo_url": row.get("repo_url"),
            "published_at": row.get("published_at"),
            "modified_at": row.get("modified_at"),
            "withdrawn_at": row.get("withdrawn_at"),
            "symbols_status": status,
            "affected": [
                {
                    "ecosystem": entry["ecosystem"],
                    "name": entry["package_name"],
                    "purl_base": entry["purl_base"],
                    "ranges": entry.get("ranges") or (),
                    "versions": entry.get("versions") or (),
                }
                for entry in affected
            ],
            "symbols": [
                {
                    "advisory_id": entry["advisory_id"],
                    "ecosystem": entry["ecosystem"],
                    "package_name": entry["package_name"],
                    "symbol": entry["symbol"],
                    "kind": entry["kind"],
                    "source": entry["source"],
                    "confidence": entry["confidence"],
                    "file_path": entry.get("file_path"),
                    "fix_commit": entry.get("fix_commit"),
                }
                for entry in symbols
            ],
        }
    )


__all__ = ["PAGE", "ExportReport", "export_snapshot"]
