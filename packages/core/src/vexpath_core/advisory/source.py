"""Where advisories come from.

Two implementations of the `AdvisorySource` protocol, with deliberately
different trade-offs:

`SnapshotSource` reads a frozen corpus from disk. It needs no network, returns
the same answer every time, and reports the snapshot identifier, which is what
makes a scan reproducible and auditable months later. This is the default for
CI and the only option for an air-gapped environment.

`OsvApiSource` queries OSV directly. It is always current and needs no local
corpus, but its answers are not reproducible, so it reports no snapshot
identifier at all. A scan built on it records that fact rather than implying a
reproducibility it does not have.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

from vexpath_core.advisory.osv import normalise
from vexpath_core.enums import canonical_ecosystem
from vexpath_core.models.advisory import Advisory
from vexpath_core.purl import normalise_name, parse_purl
from vexpath_core.snapshot import read_snapshot

#: OSV accepts up to 1000 queries per batch request.
_BATCH_SIZE = 500
_DEFAULT_TIMEOUT = 30.0


class AdvisorySourceError(Exception):
    """Raised when advisories cannot be retrieved."""


def _build_index(advisories: Sequence[Advisory]) -> dict[tuple[str, str], list[Advisory]]:
    """Index advisories by ecosystem and normalised package name.

    The keys are normalised even though advisory ingest normalises already.
    A lookup that misses produces no error at all, just a vulnerability that
    never gets reported, so the cost of normalising twice is worth paying.
    """
    index: dict[tuple[str, str], list[Advisory]] = {}
    for advisory in advisories:
        for package in advisory.affected:
            ecosystem = canonical_ecosystem(package.ecosystem)
            key = (ecosystem, normalise_name(ecosystem, package.name))
            index.setdefault(key, []).append(advisory)
    return index


class SnapshotSource:
    """Serve advisories from a frozen on-disk snapshot.

    The corpus is indexed by ecosystem and package name on construction, so a
    scan of a 500-dependency project is 500 dictionary lookups rather than 500
    passes over the corpus.
    """

    __slots__ = ("_index", "_snapshot_id")

    _index: dict[tuple[str, str], list[Advisory]]
    #: None when the corpus has no identity, as for an in-memory source built
    #: by the sync pipeline before a snapshot has been written.
    _snapshot_id: str | None

    def __init__(self, directory: Path, *, verify: bool = True) -> None:
        metadata, advisories = read_snapshot(directory, verify=verify)
        self._snapshot_id = metadata.id
        self._index = _build_index(advisories)

    @classmethod
    def from_advisories(
        cls, advisories: Sequence[Advisory], *, snapshot_id: str | None = None
    ) -> SnapshotSource:
        """Build a source from advisories already in memory.

        Used by tests and by the sync pipeline, which has the corpus in hand
        and should not write it out and read it back to query it.
        """
        source = cls.__new__(cls)
        source._index = _build_index(advisories)
        source._snapshot_id = snapshot_id
        return source

    @property
    def snapshot_id(self) -> str | None:
        return self._snapshot_id

    def advisories_for(self, purls: Sequence[str]) -> Mapping[str, Sequence[Advisory]]:
        """Return the advisories that name each purl's package.

        Version matching is not done here. This returns candidates for the
        package; deciding whether the installed version is inside an affected
        range belongs to the matcher, which can also explain its reasoning.

        Every requested purl gets an entry, so a caller can tell "no
        advisories" from "not looked up".
        """
        results: dict[str, Sequence[Advisory]] = {}
        for purl in purls:
            try:
                parts = parse_purl(purl)
            except ValueError:
                results[purl] = ()
                continue
            results[purl] = tuple(self._index.get((parts.ecosystem, parts.name), ()))
        return results

    def __len__(self) -> int:
        return sum(len(entries) for entries in self._index.values())


class OsvApiSource:
    """Query the OSV API directly.

    Results are not reproducible, so `snapshot_id` is None and any scan built
    on this source says so in its output.
    """

    __slots__ = ("_base_url", "_cache", "_client", "_owns_client")

    def __init__(
        self,
        *,
        base_url: str = "https://api.osv.dev",
        client: httpx.Client | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        # Identifier to advisory, so a dependency set that shares advisories
        # fetches each one once.
        self._cache: dict[str, Advisory] = {}

    @property
    def snapshot_id(self) -> str | None:
        """Always None: a live query cannot be reproduced."""
        return None

    def advisories_for(self, purls: Sequence[str]) -> Mapping[str, Sequence[Advisory]]:
        """Return advisories for each purl, batching the lookups."""
        results: dict[str, Sequence[Advisory]] = dict.fromkeys(purls, ())
        unique = list(dict.fromkeys(purls))

        for start in range(0, len(unique), _BATCH_SIZE):
            batch = unique[start : start + _BATCH_SIZE]
            identifiers = self._query_batch(batch)
            for purl, ids in zip(batch, identifiers, strict=True):
                advisories = [self._fetch(identifier) for identifier in ids]
                resolved = tuple(advisory for advisory in advisories if advisory is not None)
                results[purl] = _collapse_aliases(resolved)

        return results

    def _query_batch(self, purls: Sequence[str]) -> list[list[str]]:
        """Ask OSV which advisories affect each purl, returning identifiers."""
        payload = {"queries": [{"package": {"purl": purl}} for purl in purls]}
        try:
            response = self._client.post(f"{self._base_url}/v1/querybatch", json=payload)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            msg = f"OSV batch query failed: {exc}"
            raise AdvisorySourceError(msg) from exc
        except ValueError as exc:
            msg = f"OSV returned a response that is not JSON: {exc}"
            raise AdvisorySourceError(msg) from exc

        results = data.get("results", []) if isinstance(data, dict) else []
        identifiers: list[list[str]] = []
        for index in range(len(purls)):
            entry = results[index] if index < len(results) else {}
            vulns = entry.get("vulns", []) if isinstance(entry, dict) else []
            identifiers.append(
                [str(vuln["id"]) for vuln in vulns if isinstance(vuln, dict) and vuln.get("id")]
            )
        return identifiers

    def _fetch(self, identifier: str) -> Advisory | None:
        """Fetch and normalise one advisory, caching the result."""
        if identifier in self._cache:
            return self._cache[identifier]
        try:
            response = self._client.get(f"{self._base_url}/v1/vulns/{identifier}")
            response.raise_for_status()
            record: dict[str, Any] = response.json()
        except httpx.HTTPError as exc:
            msg = f"could not fetch advisory {identifier}: {exc}"
            raise AdvisorySourceError(msg) from exc
        except ValueError as exc:
            msg = f"advisory {identifier} was not valid JSON: {exc}"
            raise AdvisorySourceError(msg) from exc

        advisory = normalise(record)
        self._cache[identifier] = advisory
        # OSV aliases resolve to the same record, so cache under each of them.
        for alias in advisory.aliases:
            self._cache.setdefault(alias, advisory)
        self._cache.setdefault(identifier, advisory)
        return advisory

    def close(self) -> None:
        """Close the HTTP client, if this source created it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> OsvApiSource:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


__all__ = ["AdvisorySourceError", "OsvApiSource", "SnapshotSource"]


def _collapse_aliases(advisories: Sequence[Advisory]) -> tuple[Advisory, ...]:
    """One advisory per identifier, preferring the record that says more.

    OSV holds the same PyPI vulnerability twice: once from the GitHub
    Advisory Database as GHSA-..., once from PyPA as PYSEC-.... Both list the
    same CVE as an alias, and this project deliberately names an advisory by
    its CVE because that is what people search for and what regulation
    cites. The consequence was not handled: two records collapsed to one
    identifier and became two findings for one vulnerability, so every count
    this tool printed for a PyPI project was doubled.

    Where two records collapse, the one carrying a repository URL wins. That
    is not cosmetic: the fix commit is recovered from it, and the fix commit
    is what makes a reachability verdict possible rather than
    ``symbols_unknown``. Otherwise the first is kept, which is OSV's own
    order.
    """
    chosen: dict[str, Advisory] = {}
    for advisory in advisories:
        existing = chosen.get(advisory.id)
        first_time = existing is None
        better = existing is not None and existing.repo_url is None and advisory.repo_url
        if first_time or better:
            chosen[advisory.id] = advisory
    return tuple(chosen.values())
