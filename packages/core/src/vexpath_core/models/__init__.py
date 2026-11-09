"""Domain models shared by the CLI, the API, the workers and the database.

One definition per concept, used everywhere. The API's response bodies, the
CLI's JSON output and the database rows are all shaped by these models, which
is what stops the three from drifting apart.
"""

from __future__ import annotations

from vexpath_core.models.advisory import (
    Advisory,
    AdvisorySnapshot,
    AffectedPackage,
    AffectedRange,
    RangeEvent,
    RangeType,
    VulnerableSymbol,
)
from vexpath_core.models.common import Base, CvssScore, FileHash, Reference
from vexpath_core.models.finding import (
    AdvisoryRef,
    CallPathStep,
    ComponentRef,
    EntryPointInfo,
    Finding,
    GraphStats,
    ReachabilityResult,
)
from vexpath_core.models.results import (
    ArtifactPaths,
    PolicyResult,
    PolicyViolation,
    ProjectRef,
    SbomRef,
    ScanResults,
)
from vexpath_core.models.sbom import Component, DependencyEdge, Sbom

__all__ = [
    "Advisory",
    "AdvisoryRef",
    "AdvisorySnapshot",
    "AffectedPackage",
    "AffectedRange",
    "ArtifactPaths",
    "Base",
    "CallPathStep",
    "Component",
    "ComponentRef",
    "CvssScore",
    "DependencyEdge",
    "EntryPointInfo",
    "FileHash",
    "Finding",
    "GraphStats",
    "PolicyResult",
    "PolicyViolation",
    "ProjectRef",
    "RangeEvent",
    "RangeType",
    "ReachabilityResult",
    "Reference",
    "Sbom",
    "SbomRef",
    "ScanResults",
    "VulnerableSymbol",
]
