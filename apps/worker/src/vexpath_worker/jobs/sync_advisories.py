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
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import Engine

from vexpath_core.advisory.enrich import EnrichmentCounts
from vexpath_core.advisory.sync import DEFAULT_ECOSYSTEMS, sync
from vexpath_platform.logging import get_logger
from vexpath_worker.jobs.seed_advisories import SeedReport, seed_snapshot

log = get_logger(__name__)

#: Below this, reachability analysis cannot clear enough findings to be worth
#: much, and the product's central claim is in question. Crossing it is
#: reported loudly rather than buried in a metric nobody reads.
SYMBOL_COVERAGE_FLOOR = 0.50

#: Ecosystems with fewer advisories than this are not measured against the
#: floor. A PyPI download legitimately carries a handful of advisories that
#: also affect Maven or Hex, because one project ships bindings for several
#: languages. One advisory with no symbols is 0 % coverage, and warning about
#: it teaches people to ignore the warning that matters.
MIN_ADVISORIES_TO_JUDGE = 100


@dataclass(frozen=True, slots=True)
class SyncJobReport:
    """What a refresh produced."""

    snapshot_id: str
    advisories: int
    symbol_coverage: dict[str, float]
    skipped: int
    loaded: SeedReport | None
    #: The ecosystems the run was asked for. A download of one ecosystem also
    #: carries advisories that happen to affect others, and those are not what
    #: the run was measuring.
    requested: tuple[str, ...] = ()
    #: Advisory count per ecosystem, for deciding whether a ratio means
    #: anything.
    advisory_counts: dict[str, int] = field(default_factory=dict)
    #: How much of the corpus carries an exploitation signal, when
    #: enrichment ran. These change prioritisation, never whether a finding
    #: is reported.
    enrichment: EnrichmentCounts | None = None

    @property
    def coverage_concerns(self) -> tuple[str, ...]:
        """Ecosystems whose symbol coverage is below the usable floor.

        Only the ecosystems this run asked for, and only those with enough
        advisories for a ratio to mean anything. A warning that fires on every
        run, for ecosystems nobody requested, is a warning people learn to
        scroll past.
        """
        wanted = {name.casefold() for name in self.requested}
        concerns: list[str] = []
        for ecosystem, share in sorted(self.symbol_coverage.items()):
            if wanted and ecosystem.casefold() not in wanted:
                continue
            total = self.advisory_counts.get(ecosystem, 0)
            if total < MIN_ADVISORIES_TO_JUDGE:
                continue
            if share >= SYMBOL_COVERAGE_FLOOR:
                continue
            if share == 0.0:
                # The ordinary state of a freshly downloaded corpus: symbols
                # come from extraction, which is a separate job. Saying the
                # product's central claim is in question would be wrong.
                concerns.append(
                    f"{ecosystem} has no extracted symbols yet across "
                    f"{total} advisories, so nothing can be cleared. Run "
                    f"'vexpath-worker extract-symbols' to populate them."
                )
            else:
                concerns.append(
                    f"{ecosystem} symbol coverage is {share:.1%} across {total} "
                    f"advisories, below the {SYMBOL_COVERAGE_FLOOR:.0%} floor"
                )
        return tuple(concerns)

    def summary_line(self) -> str:
        parts = [f"snapshot {self.snapshot_id}", f"{self.advisories} advisories"]
        if self.enrichment is not None:
            parts.append(f"EPSS on {self.enrichment.epss_coverage:.1%}")
            parts.append(f"{self.enrichment.with_kev} known exploited")
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
        requested=tuple(ecosystems),
        enrichment=report.enrichment,
        advisory_counts={
            name: int(counts.get("advisories", 0))
            for name, counts in report.snapshot.counts.items()
        },
    )

    for concern in job_report.coverage_concerns:
        # Worth a warning rather than a metric: if this holds, reachability
        # cannot clear enough findings to justify the engine behind it.
        log.warning("advisory.sync.low_symbol_coverage", detail=concern)

    log.info("advisory.sync.done", summary=job_report.summary_line())
    return job_report


__all__ = [
    "MIN_ADVISORIES_TO_JUDGE",
    "SYMBOL_COVERAGE_FLOOR",
    "SyncJobReport",
    "refresh_advisories",
]
