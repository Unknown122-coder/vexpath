"""Interfaces the analysis core depends on, so it stays deterministic.

Time, network and storage never enter the core directly. They arrive as one of
these protocols, which lets the whole pipeline run offline against a frozen
advisory snapshot and produce byte-identical output. That is what makes
"same SBOM plus same snapshot equals same verdict" an enforceable claim rather
than an aspiration.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from vexpath_core.models.advisory import Advisory


@runtime_checkable
class Clock(Protocol):
    """Source of the current time."""

    def now(self) -> datetime:
        """Return the current time as an aware UTC datetime."""
        ...


class SystemClock:
    """The real clock. Used everywhere outside tests."""

    __slots__ = ()

    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    """A clock stuck at one instant, for reproducible tests and fixtures."""

    __slots__ = ("_instant",)

    def __init__(self, instant: datetime) -> None:
        if instant.tzinfo is None:
            msg = "FixedClock needs an aware datetime so results stay unambiguous"
            raise ValueError(msg)
        self._instant = instant.astimezone(UTC)

    def now(self) -> datetime:
        return self._instant


@runtime_checkable
class AdvisorySource(Protocol):
    """Where advisories come from: a frozen snapshot, a cache, or the OSV API."""

    @property
    def snapshot_id(self) -> str | None:
        """Identifier of the advisory corpus version being read.

        ``None`` means the source is live and the result is therefore not
        reproducible; scans record this so a reader can tell the difference.
        """
        ...

    def advisories_for(self, purls: Sequence[str]) -> Mapping[str, Sequence[Advisory]]:
        """Return advisories affecting each purl, keyed by the purl as given.

        Implementations must return an entry for every requested purl, using an
        empty sequence when nothing matches, so callers can distinguish "no
        advisories" from "not looked up".
        """
        ...


@runtime_checkable
class ObjectStore(Protocol):
    """Blob storage for SBOMs, VEX documents, attestations and call graphs."""

    def get(self, key: str) -> bytes:
        """Return the object at ``key``.

        Raises:
            KeyError: if the key does not exist.
        """
        ...

    def put(self, key: str, data: bytes, *, content_type: str = "application/octet-stream") -> None:
        """Store ``data`` at ``key``, replacing anything already there."""
        ...

    def exists(self, key: str) -> bool:
        """Return True if ``key`` is present."""
        ...


__all__ = ["AdvisorySource", "Clock", "FixedClock", "ObjectStore", "SystemClock"]
