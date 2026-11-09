"""Download and normalise an advisory corpus into a local snapshot.

OSV publishes a zip per ecosystem containing one JSON file per advisory. That
bulk export is what makes an offline, reproducible corpus possible, and it is
the only sensible way to fetch tens of thousands of records.

The result is written as a snapshot directory, so a scan run against it records
exactly which corpus it used. Downloading is the only part of this project that
needs the network, and it is isolated here behind an injected HTTP client so
every other stage can be tested offline.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from sscp_core.advisory.osv import normalise_all
from sscp_core.enums import canonical_ecosystem
from sscp_core.ids import new_ulid
from sscp_core.models.advisory import Advisory, AdvisorySnapshot
from sscp_core.snapshot import summarise, write_snapshot

#: Where OSV publishes its bulk exports.
OSV_EXPORT_BASE = "https://osv-vulnerabilities.storage.googleapis.com"

#: Ecosystems synced by default. Only what this project can actually act on:
#: PyPI because reachability covers it, npm because its lockfiles are parsed
#: natively. Syncing everything OSV publishes would multiply the corpus by ten
#: for data nothing consumes.
DEFAULT_ECOSYSTEMS: tuple[str, ...] = ("PyPI", "npm")

#: Refuse an export larger than this. A compressed ecosystem export is tens of
#: megabytes; an order of magnitude more means something is wrong upstream, and
#: unpacking it would exhaust a free-tier worker.
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024

_DEFAULT_TIMEOUT = 120.0


class AdvisorySyncError(Exception):
    """Raised when an advisory corpus cannot be downloaded or read."""


@dataclass(frozen=True, slots=True)
class SyncReport:
    """What a sync produced."""

    snapshot: AdvisorySnapshot
    advisories: int
    #: Records that could not be normalised, with the reason for each. Never
    #: fatal: one malformed record must not abandon a corpus of thousands.
    skipped: tuple[str, ...]

    @property
    def symbol_coverage(self) -> dict[str, float]:
        """Share of advisories per ecosystem that carry vulnerable symbols.

        This is the number the product's usefulness rests on, so it is computed
        on every sync rather than when someone thinks to ask.
        """
        coverage: dict[str, float] = {}
        for ecosystem, counts in self.snapshot.counts.items():
            total = counts.get("advisories", 0)
            coverage[ecosystem] = (counts.get("with_symbols", 0) / total) if total else 0.0
        return coverage

    def summary_line(self) -> str:
        parts = [f"{self.advisories} advisories"]
        for ecosystem, share in sorted(self.symbol_coverage.items()):
            parts.append(f"{ecosystem} symbol coverage {share:.1%}")
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped")
        return ", ".join(parts)


def sync(
    directory: Path,
    *,
    ecosystems: Sequence[str] = DEFAULT_ECOSYSTEMS,
    client: httpx.Client | None = None,
    snapshot_id: str | None = None,
) -> SyncReport:
    """Download the given ecosystems and write a snapshot to ``directory``.

    Args:
        directory: Where to write the snapshot.
        ecosystems: OSV ecosystem names to fetch.
        client: Injected HTTP client, so this is testable without network.
        snapshot_id: Identifier for the snapshot. Generated if omitted.

    Raises:
        AdvisorySyncError: if an export cannot be downloaded or read.
    """
    owns_client = client is None
    http = client or httpx.Client(timeout=_DEFAULT_TIMEOUT, follow_redirects=True)

    advisories: list[Advisory] = []
    skipped: list[str] = []
    try:
        for ecosystem in ecosystems:
            archive = _download_export(http, ecosystem)
            records = list(_records_from_archive(archive, ecosystem))
            normalised, problems = normalise_all(records)
            advisories.extend(normalised)
            skipped.extend(problems)
    finally:
        if owns_client:
            http.close()

    deduplicated = _deduplicate(advisories)
    snapshot = AdvisorySnapshot(
        id=snapshot_id or new_ulid(),
        created_at=datetime.now(UTC),
        # Recomputed from the advisories by write_snapshot.
        content_sha256="0" * 64,
        ecosystems=tuple(canonical_ecosystem(name) for name in ecosystems),
        counts=summarise(deduplicated),
    )
    stored = write_snapshot(directory, snapshot, deduplicated)
    return SyncReport(snapshot=stored, advisories=len(deduplicated), skipped=tuple(skipped))


def _download_export(client: httpx.Client, ecosystem: str) -> bytes:
    """Fetch one ecosystem's bulk export."""
    canonical = canonical_ecosystem(ecosystem)
    url = f"{OSV_EXPORT_BASE}/{canonical}/all.zip"
    try:
        response = client.get(url)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        msg = f"could not download the {canonical} advisory export from {url}: {exc}"
        raise AdvisorySyncError(msg) from exc

    content = response.content
    if len(content) > MAX_ARCHIVE_BYTES:
        msg = (
            f"the {canonical} export is {len(content)} bytes, above the "
            f"{MAX_ARCHIVE_BYTES} byte limit; refusing to unpack it"
        )
        raise AdvisorySyncError(msg)
    return content


def _records_from_archive(archive: bytes, ecosystem: str) -> Iterator[dict[str, object]]:
    """Yield OSV records from a downloaded export.

    The archive comes from a third party, so it is unpacked defensively: entry
    sizes are checked before reading, directory traversal is impossible because
    nothing is written to disk, and a malformed entry is skipped rather than
    fatal.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            for info in bundle.infolist():
                if info.is_dir() or not info.filename.endswith(".json"):
                    continue
                if info.file_size > MAX_RECORD_BYTES:
                    continue
                try:
                    with bundle.open(info) as handle:
                        record = json.loads(handle.read().decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError, zipfile.BadZipFile):
                    continue
                if isinstance(record, dict):
                    yield record
    except zipfile.BadZipFile as exc:
        msg = f"the {ecosystem} export is not a readable zip archive: {exc}"
        raise AdvisorySyncError(msg) from exc


def _deduplicate(advisories: Sequence[Advisory]) -> list[Advisory]:
    """Collapse records that describe the same vulnerability.

    The same issue appears in several ecosystem exports under different
    identifiers that alias each other. Keeping both would double-report it, so
    they merge: affected packages are unioned, and the record that carries more
    detail wins for the descriptive fields.
    """
    by_identifier: dict[str, Advisory] = {}
    canonical_for: dict[str, str] = {}

    for advisory in advisories:
        existing_key = next(
            (canonical_for[name] for name in advisory.all_ids if name in canonical_for),
            None,
        )
        if existing_key is None:
            by_identifier[advisory.id] = advisory
            for name in advisory.all_ids:
                canonical_for[name] = advisory.id
            continue

        merged = _merge(by_identifier[existing_key], advisory)
        by_identifier[existing_key] = merged
        for name in merged.all_ids:
            canonical_for.setdefault(name, existing_key)

    return sorted(by_identifier.values(), key=lambda advisory: advisory.id)


def _merge(left: Advisory, right: Advisory) -> Advisory:
    """Merge two records for the same vulnerability."""
    packages = {(p.ecosystem, p.name): p for p in left.affected}
    for package in right.affected:
        packages.setdefault((package.ecosystem, package.name), package)

    symbols = {(s.package_name, s.symbol): s for s in left.symbols}
    for symbol in right.symbols:
        symbols.setdefault((symbol.package_name, symbol.symbol), symbol)

    aliases = tuple(
        name for name in dict.fromkeys([*left.all_ids, *right.all_ids]) if name != left.id
    )

    return left.model_copy(
        update={
            "aliases": aliases,
            "summary": left.summary or right.summary,
            "details": left.details or right.details,
            # A scored severity beats an unscored one either way round.
            "severity": left.severity if left.cvss_v3 else right.severity,
            "cvss_v3": left.cvss_v3 or right.cvss_v3,
            "cvss_v4": left.cvss_v4 or right.cvss_v4,
            "cwe_ids": tuple(dict.fromkeys([*left.cwe_ids, *right.cwe_ids])),
            "references": tuple(dict.fromkeys([*left.references, *right.references])),
            "repo_url": left.repo_url or right.repo_url,
            "published_at": left.published_at or right.published_at,
            "modified_at": max(filter(None, [left.modified_at, right.modified_at]), default=None),
            "withdrawn_at": left.withdrawn_at or right.withdrawn_at,
            "affected": tuple(packages.values()),
            "symbols": tuple(symbols.values()),
        }
    )


__all__ = [
    "DEFAULT_ECOSYSTEMS",
    "MAX_ARCHIVE_BYTES",
    "OSV_EXPORT_BASE",
    "AdvisorySyncError",
    "SyncReport",
    "sync",
]
