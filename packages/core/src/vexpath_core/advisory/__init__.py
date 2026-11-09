"""Advisory ingest, normalisation and access.

The corpus is the product's factual foundation. Everything here exists to make
it trustworthy: normalised on the way in so matching cannot silently miss,
indexed so a scan is fast, and versioned as snapshots so a verdict can be
re-derived rather than merely believed.
"""

from __future__ import annotations

from vexpath_core.advisory.coverage import (
    CoverageReport,
    EcosystemCoverage,
    FixReferenceTier,
    classify_fix_reference,
    measure,
)
from vexpath_core.advisory.osv import OsvRecordError, normalise, normalise_all
from vexpath_core.advisory.source import AdvisorySourceError, OsvApiSource, SnapshotSource
from vexpath_core.advisory.sync import AdvisorySyncError, SyncReport, sync

__all__ = [
    "AdvisorySourceError",
    "AdvisorySyncError",
    "CoverageReport",
    "EcosystemCoverage",
    "FixReferenceTier",
    "OsvApiSource",
    "OsvRecordError",
    "SnapshotSource",
    "SyncReport",
    "classify_fix_reference",
    "measure",
    "normalise",
    "normalise_all",
    "sync",
]
