"""Refresh exploitation signals over the stored corpus.

EPSS is recomputed every day; the advisory corpus is not. Re-downloading tens
of megabytes of OSV exports to pick up new probabilities would be the wrong
trade, so this job updates the two signal columns in place and nothing else.

It is also the job that corrects the record when CISA adds something to the
Known Exploited Vulnerabilities catalogue, which is the single most actionable
thing either feed says and the one worth knowing the same day.

Nothing here can change whether a finding is reported. Only `epss_score`,
`epss_percentile`, `kev` and `kev_added_at` are written, and every other column
is left exactly as the sync left it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx
from sqlalchemy import Engine, bindparam, select, update

from vexpath_core.advisory.enrich import ExploitSignals, fetch_signals
from vexpath_db.tables import advisories
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

#: Rows updated per statement. Large enough that the round trips do not
#: dominate, small enough that one failed batch is cheap to redo.
BATCH = 1000


@dataclass(frozen=True, slots=True)
class EnrichJobReport:
    """What a refresh changed."""

    advisories: int
    epss_updated: int
    kev_updated: int
    kev_newly_listed: int
    #: Advisories carrying a CVE identifier. Both feeds are keyed by CVE, so
    #: anything else is out of scope rather than a miss: on the real corpus
    #: 12,003 of 19,552 records are malicious-package entries with no CVE, and
    #: dividing by the whole corpus turns 89 per cent coverage into 34.
    scorable: int = 0
    failures: tuple[str, ...] = ()

    @property
    def epss_coverage(self) -> float:
        denominator = self.scorable or self.advisories
        return self.epss_updated / denominator if denominator else 0.0

    @property
    def out_of_scope(self) -> int:
        return max(self.advisories - (self.scorable or self.advisories), 0)

    def summary_line(self) -> str:
        parts = [
            f"{self.advisories} advisories",
            f"{self.epss_updated} of {self.scorable or self.advisories} with a CVE "
            f"have an EPSS score ({self.epss_coverage:.1%})",
            f"{self.kev_updated} known exploited",
        ]
        if self.out_of_scope:
            parts.append(f"{self.out_of_scope} with no CVE identifier")
        if self.kev_newly_listed:
            parts.append(f"{self.kev_newly_listed} newly listed")
        if self.failures:
            parts.append(f"{len(self.failures)} feed(s) unavailable")
        return ", ".join(parts)


def refresh_signals(
    engine: Engine,
    *,
    signals: ExploitSignals | None = None,
    client: httpx.Client | None = None,
    cache_dir: Path | None = None,
) -> EnrichJobReport:
    """Update every stored advisory's exploitation signals.

    Args:
        engine: Database holding the corpus.
        signals: Pre-fetched signals instead of downloading. Injected so tests
            run offline.
        client: HTTP client for the download.
        cache_dir: Reserved for a cached copy of the feeds; unused today and
            accepted so the command's shape does not change when it lands.

    Returns:
        What was updated. A feed that could not be read is reported rather than
        raised: the corpus is still correct without it, and failing would mean
        one third party's outage stops the whole refresh.
    """
    del cache_dir
    resolved = signals if signals is not None else fetch_signals(client=client)
    if resolved.is_empty:
        log.warning("advisory.enrich.no_signals", failures=list(resolved.failures))
        return EnrichJobReport(0, 0, 0, 0, failures=resolved.failures)

    log.info("advisory.enrich.start", detail=resolved.summary_line())

    with engine.connect() as connection:
        rows = connection.execute(
            select(advisories.c.id, advisories.c.aliases, advisories.c.kev)
        ).all()

    updates: list[dict[str, object]] = []
    newly_listed = 0
    scorable = 0
    for identifier, aliases, was_listed in rows:
        keys = [identifier.upper(), *(alias.upper() for alias in (aliases or ()))]
        scorable += 1 if any(key.startswith("CVE-") for key in keys) else 0
        score = next((resolved.epss[key] for key in keys if key in resolved.epss), None)
        added = next((resolved.kev[key] for key in keys if key in resolved.kev), None)
        if score is None and added is None:
            continue
        if added is not None and not was_listed:
            # Worth counting on its own: something moved from predicted to
            # observed exploitation, which is the most actionable change
            # either feed can report.
            newly_listed += 1
        updates.append(
            {
                "row_id": identifier,
                "epss_score": score.score if score else None,
                "epss_percentile": score.percentile if score else None,
                "kev": added is not None,
                "kev_added_at": added,
            }
        )

    statement = (
        update(advisories)
        .where(advisories.c.id == bindparam("row_id"))
        .values(
            epss_score=bindparam("epss_score"),
            epss_percentile=bindparam("epss_percentile"),
            kev=bindparam("kev"),
            kev_added_at=bindparam("kev_added_at"),
        )
    )
    for start in range(0, len(updates), BATCH):
        chunk = updates[start : start + BATCH]
        with engine.begin() as connection:
            connection.execute(statement, chunk)

    report = EnrichJobReport(
        advisories=len(rows),
        epss_updated=sum(1 for row in updates if row["epss_score"] is not None),
        kev_updated=sum(1 for row in updates if row["kev"]),
        kev_newly_listed=newly_listed,
        scorable=scorable,
        failures=resolved.failures,
    )
    log.info("advisory.enrich.done", summary=report.summary_line())
    if report.kev_newly_listed:
        log.warning(
            "advisory.enrich.newly_exploited",
            count=report.kev_newly_listed,
            detail="advisories moved into the CISA Known Exploited catalogue",
        )
    return report


__all__ = ["BATCH", "EnrichJobReport", "refresh_signals"]
