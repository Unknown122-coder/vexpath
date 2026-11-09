"""Refresh the advisory corpus: download, snapshot, then load.

Two steps that are deliberately separate. Downloading writes a snapshot
directory, which is an artefact in its own right: it is what an air-gapped
environment copies in, and what a CI job publishes so every scan that week is
reproducible. Loading reads that snapshot into the database for the platform's
own queries.

Keeping them apart means a failed load does not cost another download, and a
snapshot can be inspected before it is trusted.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine

from sscp_core.advisory.sync import DEFAULT_ECOSYSTEMS, sync
from sscp_platform.logging import get_logger
from sscp_worker.jobs.seed_advisories import SeedReport, seed_snapshot

log = get_logger(__name__)

#: Below this, reachability analysis cannot clear enough findings to be worth
#: much, and the product's central claim is in question. Crossing it is
#: reported loudly rather than buried in a metric nobody reads.
SYMBOL_COVERAGE_FLOOR = 0.50


@dataclass(frozen=True, slots=True)
class SyncJobReport:
    """What a refresh produced."""

    snapshot_id: str
    advisories: int
    symbol_coverage: dict[str, float]
    skipped: int
    loaded: SeedReport | None

    @property
    def coverage_concerns(self) -> tuple[str, ...]:
        """Ecosystems whose symbol coverage is below the usable floor."""
        return tuple(
            f"{ecosystem} symbol coverage is {share:.1%}, below the "
            f"{SYMBOL_COVERAGE_FLOOR:.0%} floor"
            for ecosystem, share in sorted(self.symbol_coverage.items())
            if share < SYMBOL_COVERAGE_FLOOR
        )

    def summary_line(self) -> str:
        parts = [f"snapshot {self.snapshot_id}", f"{self.advisories} advisories"]
        for ecosystem, share in sorted(self.symbol_coverage.items()):
            parts.append(f"{ecosystem} symbols {share:.1%}")
        if self.skipped:
            parts.append(f"{self.skipped} skipped")
        if self.loaded is not None:
            parts.append("loaded into the database")
        return ", ".join(parts)


def refresh_advisories(
    directory: Path,
    *,
    engine: Engine | None = None,
    ecosystems: Sequence[str] = DEFAULT_ECOSYSTEMS,
) -> SyncJobReport:
    """Download a fresh corpus, write it as a snapshot, and optionally load it.

    Args:
        directory: Where to write the snapshot.
        engine: When given, load the snapshot into this database. When omitted,
            the snapshot is written and nothing else, which is what a job
            publishing a snapshot artefact wants.
        ecosystems: OSV ecosystem names to download.
    """
    log.info("advisory.sync.start", ecosystems=list(ecosystems), directory=str(directory))
    report = sync(directory, ecosystems=ecosystems)

    coverage = report.symbol_coverage
    log.info(
        "advisory.sync.downloaded",
        snapshot_id=report.snapshot.id,
        advisories=report.advisories,
        skipped=len(report.skipped),
        **{f"coverage_{name}": round(share, 4) for name, share in coverage.items()},
    )

    loaded: SeedReport | None = None
    if engine is not None:
        loaded = seed_snapshot(engine, directory)

    job_report = SyncJobReport(
        snapshot_id=report.snapshot.id,
        advisories=report.advisories,
        symbol_coverage=coverage,
        skipped=len(report.skipped),
        loaded=loaded,
    )

    for concern in job_report.coverage_concerns:
        # Worth a warning rather than a metric: if this holds, reachability
        # cannot clear enough findings to justify the engine behind it.
        log.warning("advisory.sync.low_symbol_coverage", detail=concern)

    log.info("advisory.sync.done", summary=job_report.summary_line())
    return job_report


__all__ = ["SYMBOL_COVERAGE_FLOOR", "SyncJobReport", "refresh_advisories"]
