"""Advisory ingest, normalisation and access.

The corpus is the product's factual foundation. Everything here exists to make
it trustworthy: normalised on the way in so matching cannot silently miss,
indexed so a scan is fast, and versioned as snapshots so a verdict can be
re-derived rather than merely believed.
"""

from __future__ import annotations

from sscp_core.advisory.osv import OsvRecordError, normalise, normalise_all
from sscp_core.advisory.source import AdvisorySourceError, OsvApiSource, SnapshotSource
from sscp_core.advisory.sync import AdvisorySyncError, SyncReport, sync

__all__ = [
    "AdvisorySourceError",
    "AdvisorySyncError",
    "OsvApiSource",
    "OsvRecordError",
    "SnapshotSource",
    "SyncReport",
    "normalise",
    "normalise_all",
    "sync",
]
