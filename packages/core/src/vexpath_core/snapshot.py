"""Advisory snapshots: the mechanism behind reproducible scans.

A scan records the identifier of the advisory corpus it read. Months later the
same SBOM and the same snapshot must produce the same verdicts, which is what
lets a verdict be audited rather than merely trusted.

Two hashes make that work:

``advisory_source_hash``
    Covers an advisory's identity, descriptive content and affected ranges.
    It deliberately excludes daily enrichment (EPSS scores change every day)
    and derived data (vulnerable symbols appear later, when patch diffing
    runs). Without those exclusions the hash would churn constantly and stop
    being useful for change detection.

``snapshot_content_hash``
    Covers every advisory's source hash. Two snapshots with the same content
    hash are the same corpus.

On-disk layout of a snapshot directory::

    snapshot.json      metadata: id, created_at, content_sha256, ecosystems, counts
    advisories.jsonl   one normalised Advisory per line, sorted by id
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from vexpath_core import __version__ as core_version
from vexpath_core.models.advisory import Advisory, AdvisorySnapshot

SNAPSHOT_METADATA_FILE = "snapshot.json"
ADVISORIES_FILE = "advisories.jsonl"

#: Excluded from an advisory's source hash. See the module docstring.
_VOLATILE_FIELDS = frozenset(
    {
        "source_sha256",
        "symbols",
        "symbols_status",
        "epss_score",
        "epss_percentile",
        "kev",
        "kev_added_at",
    }
)


def canonical_json(payload: Any) -> str:
    """Serialise to the one JSON form this project hashes.

    Keys sorted, no insignificant whitespace, Unicode preserved. Any change
    here changes every hash, so it is defined once and never varied.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def advisory_source_hash(advisory: Advisory) -> str:
    """Return the SHA-256 of an advisory's stable content."""
    payload = advisory.model_dump(mode="json", exclude=set(_VOLATILE_FIELDS))
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def snapshot_content_hash(source_hashes: Iterable[str]) -> str:
    """Return the SHA-256 identifying a whole corpus.

    Sorted before hashing, so the order advisories were synced in does not
    change the result.
    """
    joined = "\n".join(sorted(source_hashes))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def with_source_hashes(advisories: Iterable[Advisory]) -> tuple[Advisory, ...]:
    """Return the advisories with ``source_sha256`` filled in."""
    return tuple(
        advisory.model_copy(update={"source_sha256": advisory_source_hash(advisory)})
        for advisory in advisories
    )


def summarise(advisories: Sequence[Advisory]) -> dict[str, dict[str, int]]:
    """Count advisories per ecosystem, and how many have vulnerable symbols.

    Symbol coverage is the number the product's usefulness depends on, so it is
    recorded in every snapshot rather than computed ad hoc when someone asks.
    """
    counts: dict[str, dict[str, int]] = {}
    for advisory in advisories:
        ecosystems = {package.ecosystem for package in advisory.affected}
        has_symbols = bool(advisory.symbols)
        for ecosystem in ecosystems:
            bucket = counts.setdefault(ecosystem, {"advisories": 0, "with_symbols": 0})
            bucket["advisories"] += 1
            if has_symbols:
                bucket["with_symbols"] += 1
    return counts


class SnapshotIntegrityError(Exception):
    """Raised when a snapshot's recorded hash disagrees with its contents.

    This is always treated as fatal. A corrupted or tampered advisory corpus
    changes verdicts, so loading one is never an acceptable degraded mode.
    """


def read_snapshot(
    directory: Path, *, verify: bool = True
) -> tuple[AdvisorySnapshot, tuple[Advisory, ...]]:
    """Read a snapshot directory.

    Args:
        directory: Directory holding ``snapshot.json`` and ``advisories.jsonl``.
        verify: Recompute the content hash and compare it with the recorded
            one. Leave this on except when deliberately inspecting a snapshot
            known to be inconsistent.

    Raises:
        FileNotFoundError: if either file is missing.
        SnapshotIntegrityError: if verification fails.
    """
    metadata_path = directory / SNAPSHOT_METADATA_FILE
    advisories_path = directory / ADVISORIES_FILE
    for path in (metadata_path, advisories_path):
        if not path.is_file():
            msg = f"not a snapshot directory, {path.name} is missing: {directory}"
            raise FileNotFoundError(msg)

    metadata = AdvisorySnapshot.model_validate_json(metadata_path.read_text(encoding="utf-8"))

    advisories: list[Advisory] = []
    with advisories_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                advisories.append(Advisory.model_validate_json(stripped))
            except ValueError as exc:
                msg = f"{advisories_path}:{line_number}: {exc}"
                raise SnapshotIntegrityError(msg) from exc

    resolved = with_source_hashes(advisories)
    if verify:
        computed = snapshot_content_hash(
            advisory.source_sha256 for advisory in resolved if advisory.source_sha256
        )
        if computed != metadata.content_sha256:
            raise SnapshotIntegrityError(_mismatch_message(metadata, computed))

    return metadata, resolved


def _mismatch_message(metadata: AdvisorySnapshot, computed: str) -> str:
    """Explain a hash mismatch in terms of its likely cause.

    The content hash covers the *normalised* advisory records, so improving
    normalisation changes the hash of a corpus whose bytes never moved. That is
    the ordinary case and it has an obvious remedy. Corruption or tampering is
    the rare case and has a different one. Reporting both the same way sends a
    reader hunting for damage that is not there.
    """
    written_by = metadata.core_version
    if written_by is not None and written_by != core_version:
        return (
            f"snapshot {metadata.id} was normalised by vexpath-core {written_by} "
            f"and this is {core_version}. The content hash covers the normalised "
            f"records, so a normalisation change alters it even though the data "
            f"is unchanged. Re-run 'vexpath advisory sync' to rebuild the "
            f"snapshot with this version."
        )
    return (
        f"snapshot {metadata.id} does not match its contents: recorded "
        f"{metadata.content_sha256}, computed {computed}. Either the files were "
        f"modified after being written, or they were produced by a build that "
        f"did not record its version. Re-sync rather than trusting it: a "
        f"corrupted corpus changes verdicts."
    )


def write_snapshot(
    directory: Path, snapshot: AdvisorySnapshot, advisories: Sequence[Advisory]
) -> AdvisorySnapshot:
    """Write a snapshot directory and return the metadata actually stored.

    The content hash and counts are recomputed from the advisories rather than
    taken from the argument, so a snapshot on disk is always self-consistent.
    """
    directory.mkdir(parents=True, exist_ok=True)
    resolved = with_source_hashes(advisories)
    ordered = sorted(resolved, key=lambda advisory: advisory.id)

    stored = snapshot.model_copy(
        update={
            "content_sha256": snapshot_content_hash(
                advisory.source_sha256 for advisory in ordered if advisory.source_sha256
            ),
            "counts": summarise(ordered),
            "ecosystems": tuple(sorted(summarise(ordered))),
            # Always this build, never whatever the caller passed: the hash
            # just computed describes this version's normalisation.
            "core_version": core_version,
        }
    )

    # newline="\n" explicitly, rather than the platform default: a snapshot
    # written on Windows must be byte-identical to one written on Linux, or the
    # generated-output check in CI fails for a reason unrelated to the data.
    lines = [canonical_json(advisory.model_dump(mode="json")) for advisory in ordered]
    (directory / ADVISORIES_FILE).write_text(
        "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
    )
    (directory / SNAPSHOT_METADATA_FILE).write_text(
        json.dumps(stored.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return stored


__all__ = [
    "ADVISORIES_FILE",
    "SNAPSHOT_METADATA_FILE",
    "SnapshotIntegrityError",
    "advisory_source_hash",
    "canonical_json",
    "read_snapshot",
    "snapshot_content_hash",
    "summarise",
    "with_source_hashes",
    "write_snapshot",
]
