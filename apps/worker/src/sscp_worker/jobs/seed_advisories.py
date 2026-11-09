"""Load a frozen advisory snapshot into the database.

Used to seed a development database and the integration test database from
``testdata/advisories``, so that the whole pipeline can be exercised with no
network access.

The job is idempotent: an advisory's child rows are replaced wholesale rather
than merged, so running it twice leaves exactly the same state. That matters
because the real ``advisory.sync`` job (M1) uses this same write path and will
be retried.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine, delete
from sqlalchemy.dialects.postgresql import Insert as PgInsert
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sscp_core.ids import new_ulid
from sscp_core.models.advisory import Advisory
from sscp_core.snapshot import read_snapshot
from sscp_db.tables import advisories, advisory_affected, advisory_snapshots, vulnerable_symbols
from sscp_platform.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class SeedReport:
    """What a seeding run changed."""

    snapshot_id: str
    content_sha256: str
    advisories: int
    affected_packages: int
    symbols: int

    def summary_line(self) -> str:
        return (
            f"snapshot {self.snapshot_id}: {self.advisories} advisories, "
            f"{self.affected_packages} affected packages, {self.symbols} vulnerable symbols"
        )


def seed_snapshot(engine: Engine, directory: Path) -> SeedReport:
    """Load the snapshot in ``directory`` into the database.

    Everything happens in one transaction, so a failure part-way leaves the
    advisory corpus as it was rather than half-updated.

    Raises:
        FileNotFoundError: if the directory is not a snapshot.
        SnapshotIntegrityError: if the snapshot's hash does not match contents.
    """
    metadata, records = read_snapshot(directory)
    log.info(
        "seed.start",
        snapshot_id=metadata.id,
        advisories=len(records),
        directory=str(directory),
    )

    affected_rows = 0
    symbol_rows = 0

    with engine.begin() as connection:
        for advisory in records:
            connection.execute(_advisory_upsert(advisory))

            # Replace rather than merge: an advisory's affected ranges and
            # symbols are a single fact that the source owns completely.
            connection.execute(
                delete(advisory_affected).where(advisory_affected.c.advisory_id == advisory.id)
            )
            connection.execute(
                delete(vulnerable_symbols).where(vulnerable_symbols.c.advisory_id == advisory.id)
            )

            affected_values = [
                {
                    "id": new_ulid(),
                    "advisory_id": advisory.id,
                    "ecosystem": package.ecosystem,
                    "package_name": package.name,
                    "purl_base": package.purl_base,
                    "ranges": [r.model_dump(mode="json") for r in package.ranges],
                    "versions": list(package.versions),
                    "fixed_versions": list(package.fixed_versions),
                }
                for package in advisory.affected
            ]
            if affected_values:
                connection.execute(advisory_affected.insert(), affected_values)
                affected_rows += len(affected_values)

            symbol_values = [
                {
                    "id": new_ulid(),
                    "advisory_id": advisory.id,
                    "ecosystem": symbol.ecosystem,
                    "package_name": symbol.package_name,
                    "symbol": symbol.symbol,
                    "kind": symbol.kind.value,
                    "source": symbol.source.value,
                    "confidence": symbol.confidence.value,
                    "file_path": symbol.file_path,
                    "fix_commit": symbol.fix_commit,
                }
                for symbol in advisory.symbols
            ]
            if symbol_values:
                connection.execute(vulnerable_symbols.insert(), symbol_values)
                symbol_rows += len(symbol_values)

        connection.execute(
            pg_insert(advisory_snapshots)
            .values(
                id=metadata.id,
                content_sha256=metadata.content_sha256,
                ecosystems=list(metadata.ecosystems),
                counts=metadata.counts,
                created_at=metadata.created_at,
            )
            # A snapshot is identified by its content, so re-seeding the same
            # corpus must not create a second row.
            .on_conflict_do_update(
                index_elements=[advisory_snapshots.c.content_sha256],
                set_={"counts": metadata.counts, "ecosystems": list(metadata.ecosystems)},
            )
        )

    report = SeedReport(
        snapshot_id=metadata.id,
        content_sha256=metadata.content_sha256,
        advisories=len(records),
        affected_packages=affected_rows,
        symbols=symbol_rows,
    )
    log.info("seed.done", **{k: getattr(report, k) for k in ("advisories", "symbols")})
    return report


def _advisory_upsert(advisory: Advisory) -> PgInsert:
    """Build the upsert statement for one advisory row."""
    values = {
        "id": advisory.id,
        "aliases": list(advisory.aliases),
        "summary": advisory.summary,
        "details": advisory.details,
        "severity": advisory.severity.value,
        "cvss_v3": advisory.cvss_v3.model_dump(mode="json") if advisory.cvss_v3 else None,
        "cvss_v4": advisory.cvss_v4.model_dump(mode="json") if advisory.cvss_v4 else None,
        "epss_score": advisory.epss_score,
        "epss_percentile": advisory.epss_percentile,
        "kev": advisory.kev,
        "kev_added_at": advisory.kev_added_at,
        "cwe_ids": list(advisory.cwe_ids),
        "references": [reference.model_dump(mode="json") for reference in advisory.references],
        "repo_url": advisory.repo_url,
        "published_at": advisory.published_at,
        "modified_at": advisory.modified_at,
        "withdrawn_at": advisory.withdrawn_at,
        "symbols_status": advisory.symbols_status.value,
        "source_sha256": advisory.source_sha256,
    }
    statement = pg_insert(advisories).values(**values)
    return statement.on_conflict_do_update(
        index_elements=[advisories.c.id],
        set_={key: value for key, value in values.items() if key != "id"},
    )


__all__ = ["SeedReport", "seed_snapshot"]
