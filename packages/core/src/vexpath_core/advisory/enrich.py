"""Exploitation signals: EPSS probabilities and the CISA KEV catalogue.

These change what to fix first, never whether something is reported. A
reachable critical with an EPSS score of 0.002 and a reachable medium that
appears in the Known Exploited Vulnerabilities catalogue are not the same
problem, and severity alone cannot tell them apart.

Both feeds are keyed by CVE identifier, which is why an advisory's aliases
matter: a GHSA-primary record carries its CVE as an alias, and looking up only
the primary identifier would miss most of the corpus.

Two properties shape the implementation.

**A missing feed is not a failed sync.** Enrichment is advisory data about
advisory data. If EPSS is unreachable, the corpus is still correct and still
usable, so a failure is reported and the corpus is written without it. The
alternative, failing the whole sync, would mean one third party's outage stops
a security tool from updating.

**A stale score is worse than none for the KEV flag.** EPSS is a probability
that ages gracefully; KEV membership is a statement that something is being
exploited right now. Both are stamped with the date they were read so a reader
can see how old the answer is.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

import httpx

from vexpath_core.models.advisory import Advisory

#: Daily EPSS export. Gzipped CSV with a comment line, then a header, then one
#: row per CVE.
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

#: The CISA Known Exploited Vulnerabilities catalogue.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

#: Refuse a download larger than this. EPSS is a few megabytes compressed and
#: KEV is under one; an order of magnitude more means something is wrong
#: upstream, and parsing it would exhaust a small worker.
MAX_FEED_BYTES = 128 * 1024 * 1024

_DEFAULT_TIMEOUT = 60.0


class EnrichmentError(Exception):
    """Raised when a feed cannot be downloaded or parsed.

    Callers are expected to carry on without the signal rather than abandon a
    corpus over it.
    """


@dataclass(frozen=True, slots=True)
class EpssScore:
    """One CVE's probability of exploitation in the next 30 days."""

    score: float
    percentile: float


@dataclass(slots=True)
class ExploitSignals:
    """Everything the two feeds know, keyed by CVE identifier."""

    epss: dict[str, EpssScore] = field(default_factory=dict)
    #: CVE identifier to the date CISA added it to the catalogue.
    kev: dict[str, date] = field(default_factory=dict)
    #: When these were read. Stamped because KEV is a statement about now.
    read_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    #: Feeds that could not be read, and why. Never fatal.
    failures: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.epss and not self.kev

    def summary_line(self) -> str:
        parts = [f"{len(self.epss)} EPSS scores", f"{len(self.kev)} KEV entries"]
        if self.failures:
            parts.append(f"{len(self.failures)} feed(s) unavailable")
        return ", ".join(parts)


def fetch_signals(
    *,
    client: httpx.Client | None = None,
    epss_url: str = EPSS_URL,
    kev_url: str = KEV_URL,
) -> ExploitSignals:
    """Download both feeds, tolerating the failure of either.

    Args:
        client: HTTP client to use. Injected so tests run offline.
        epss_url: Override for the EPSS export.
        kev_url: Override for the KEV catalogue.

    Returns:
        What could be read, and a note for whatever could not.
    """
    http = client or httpx.Client(timeout=_DEFAULT_TIMEOUT, follow_redirects=True)
    failures: list[str] = []
    epss: dict[str, EpssScore] = {}
    kev: dict[str, date] = {}

    try:
        epss = parse_epss(_download(http, epss_url))
    except EnrichmentError as exc:
        failures.append(f"EPSS: {exc}")

    try:
        kev = parse_kev(_download(http, kev_url))
    except EnrichmentError as exc:
        failures.append(f"KEV: {exc}")

    if client is None:
        http.close()

    return ExploitSignals(epss=epss, kev=kev, failures=tuple(failures))


def _download(client: httpx.Client, url: str) -> bytes:
    try:
        response = client.get(url)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        msg = f"could not download {url}: {exc}"
        raise EnrichmentError(msg) from exc

    if len(response.content) > MAX_FEED_BYTES:
        msg = f"{url} returned {len(response.content)} bytes, above the {MAX_FEED_BYTES} limit"
        raise EnrichmentError(msg)
    return response.content


def parse_epss(payload: bytes) -> dict[str, EpssScore]:
    """Parse the EPSS export, gzipped or not.

    The file begins with a comment line naming the model version and date,
    then a header row. Rows whose score is unparseable are skipped rather than
    failing the file: a prioritisation signal missing for one CVE is a far
    smaller problem than no signal for any.
    """
    text = _maybe_gunzip(payload).decode("utf-8", errors="replace")
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    if not lines:
        msg = "the EPSS export has no rows"
        raise EnrichmentError(msg)

    scores: dict[str, EpssScore] = {}
    for row in csv.DictReader(lines):
        identifier = (row.get("cve") or "").strip().upper()
        if not identifier:
            continue
        try:
            scores[identifier] = EpssScore(
                score=float(row.get("epss") or 0.0),
                percentile=float(row.get("percentile") or 0.0),
            )
        except (TypeError, ValueError):
            continue

    if not scores:
        msg = "the EPSS export parsed to no scores, so its format has probably changed"
        raise EnrichmentError(msg)
    return scores


def parse_kev(payload: bytes) -> dict[str, date]:
    """Parse the KEV catalogue into CVE identifier and date added."""
    try:
        document = json.loads(_maybe_gunzip(payload).decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        msg = f"the KEV catalogue is not readable JSON: {exc}"
        raise EnrichmentError(msg) from exc

    if not isinstance(document, dict):
        msg = "the KEV catalogue is not a JSON object"
        raise EnrichmentError(msg)

    entries = document.get("vulnerabilities")
    if not isinstance(entries, list):
        msg = "the KEV catalogue has no 'vulnerabilities' array"
        raise EnrichmentError(msg)

    found: dict[str, date] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        identifier = str(entry.get("cveID") or "").strip().upper()
        if not identifier:
            continue
        found[identifier] = _parse_date(entry.get("dateAdded"))

    if not found:
        msg = "the KEV catalogue parsed to no entries, so its format has probably changed"
        raise EnrichmentError(msg)
    return found


def _parse_date(raw: object) -> date:
    """Read a KEV date, falling back to today when it is unreadable.

    The date is presentational. Refusing a catalogue entry over an unparseable
    date would drop a statement that something is actively exploited, which is
    the most important thing either feed says.
    """
    try:
        return date.fromisoformat(str(raw))
    except (TypeError, ValueError):
        return datetime.now(UTC).date()


def _maybe_gunzip(payload: bytes) -> bytes:
    """Decompress if the payload is gzipped, otherwise return it unchanged."""
    if payload[:2] != b"\x1f\x8b":
        return payload
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as handle:
            return handle.read(MAX_FEED_BYTES + 1)
    except OSError as exc:
        msg = f"the feed is gzipped but could not be decompressed: {exc}"
        raise EnrichmentError(msg) from exc


def enrich(advisory: Advisory, signals: ExploitSignals) -> Advisory:
    """Attach exploitation signals to one advisory.

    Looked up by every identifier the advisory carries, not just the primary
    one. A GHSA-primary record holds its CVE as an alias, and both feeds are
    keyed by CVE, so matching only the primary identifier would miss most of
    the corpus.

    Returns the advisory unchanged when neither feed knows it, so an unenriched
    record is distinguishable from one scored zero. A real EPSS score of 0.0 is
    meaningful: it says exploitation is very unlikely.
    """
    update: dict[str, object] = {}

    for identifier in advisory.all_ids:
        key = identifier.upper()
        if "epss_score" not in update and (score := signals.epss.get(key)) is not None:
            update["epss_score"] = score.score
            update["epss_percentile"] = score.percentile
        if "kev" not in update and (added := signals.kev.get(key)) is not None:
            update["kev"] = True
            update["kev_added_at"] = added

    return advisory.model_copy(update=update) if update else advisory


def enrich_all(
    advisories: Iterable[Advisory], signals: ExploitSignals
) -> tuple[tuple[Advisory, ...], EnrichmentCounts]:
    """Attach signals to a whole corpus, and count what landed."""
    enriched: list[Advisory] = []
    with_epss = 0
    with_kev = 0
    scorable = 0
    for advisory in advisories:
        result = enrich(advisory, signals)
        enriched.append(result)
        with_epss += 1 if result.epss_score is not None else 0
        with_kev += 1 if result.kev else 0
        scorable += 1 if has_cve_identifier(result) else 0
    return tuple(enriched), EnrichmentCounts(
        advisories=len(enriched),
        with_epss=with_epss,
        with_kev=with_kev,
        scorable=scorable,
    )


def has_cve_identifier(advisory: Advisory) -> bool:
    """Whether either feed could possibly know this advisory.

    Both are keyed by CVE. A malicious-package record has no CVE and never
    will, so counting it as an enrichment miss understates coverage.
    """
    return any(identifier.upper().startswith("CVE-") for identifier in advisory.all_ids)


@dataclass(frozen=True, slots=True)
class EnrichmentCounts:
    """How much of a corpus carries each signal."""

    advisories: int
    with_epss: int
    with_kev: int
    #: Advisories that could have a score at all. Both feeds are keyed by CVE,
    #: so a record with no CVE identifier anywhere is not a miss, it is out of
    #: scope. On the real corpus that is 12,003 of 19,552 records, and dividing
    #: by the wrong one of those turns 89 per cent coverage into 34 per cent.
    scorable: int = 0

    @property
    def epss_coverage(self) -> float:
        """Share of the advisories that could be scored, and were."""
        denominator = self.scorable or self.advisories
        return self.with_epss / denominator if denominator else 0.0

    @property
    def out_of_scope(self) -> int:
        return max(self.advisories - (self.scorable or self.advisories), 0)

    def summary_line(self) -> str:
        line = (
            f"{self.with_epss} of {self.scorable or self.advisories} advisories "
            f"with a CVE identifier have an EPSS score ({self.epss_coverage:.1%}), "
            f"{self.with_kev} are known exploited"
        )
        if self.out_of_scope:
            line += (
                f". {self.out_of_scope} record(s) carry no CVE identifier, so no "
                f"feed can score them"
            )
        return line


def highest_priority(advisories: Iterable[Advisory], *, limit: int = 10) -> tuple[Advisory, ...]:
    """The advisories to look at first, worst plausible outcome soonest.

    Known exploited comes before everything: it is not a prediction. After
    that, EPSS descending, then severity, so a medium being actively exploited
    outranks a critical that nobody has worked out how to use.
    """
    ordered = sorted(
        advisories,
        key=lambda advisory: (
            not advisory.kev,
            -(advisory.epss_score or 0.0),
            -advisory.severity.rank,
            advisory.id,
        ),
    )
    return tuple(ordered[:limit])


def signals_from_mapping(
    epss: Mapping[str, tuple[float, float]], kev: Mapping[str, date]
) -> ExploitSignals:
    """Build signals from plain data, for tests and for a cached feed."""
    return ExploitSignals(
        epss={
            identifier.upper(): EpssScore(score=score, percentile=percentile)
            for identifier, (score, percentile) in epss.items()
        },
        kev={identifier.upper(): added for identifier, added in kev.items()},
    )


__all__ = [
    "EPSS_URL",
    "KEV_URL",
    "MAX_FEED_BYTES",
    "EnrichmentCounts",
    "EnrichmentError",
    "EpssScore",
    "ExploitSignals",
    "enrich",
    "enrich_all",
    "fetch_signals",
    "has_cve_identifier",
    "highest_priority",
    "parse_epss",
    "parse_kev",
    "signals_from_mapping",
]
