"""Reachability analysis: can the vulnerable code actually run?

This is what separates this tool from a dependency scanner. Everything else in
the project exists to feed it or to publish what it concludes.

The shape of it:

1. **Build** a call graph per package version, cached, plus one for the
   project's own code (:mod:`vexpath_core.reach.pybuild`).
2. **Link** them, which is a dictionary union rather than a rebuild
   (:func:`vexpath_core.reach.graph.link`).
3. **Search** from the project's entry points, twice: once over resolved calls
   alone and once over every edge, so a path that exists is distinguishable
   from a path that might (:func:`vexpath_core.reach.graph.search`).
4. **Decide**, mapping what was reached onto a verdict with its evidence
   (:mod:`vexpath_core.reach.verdict`).

Python only, by decision (ADR-0012). Components from other ecosystems are
reported as unchecked rather than cleared.
"""

from __future__ import annotations

from vexpath_core.reach.entrypoints import Detected, choose, is_inferred
from vexpath_core.reach.graph import (
    BUILDER_VERSION,
    CallGraph,
    Edge,
    GraphQuality,
    Node,
    PathStep,
    SearchResult,
    expand_targets,
    link,
    matched_symbols,
    search,
)
from vexpath_core.reach.pybuild import SourceRoot, build, detect_entry_points
from vexpath_core.reach.verdict import ReachabilityContext, apply, decide, mentioned_symbols

__all__ = [
    "BUILDER_VERSION",
    "CallGraph",
    "Detected",
    "Edge",
    "GraphQuality",
    "Node",
    "PathStep",
    "ReachabilityContext",
    "SearchResult",
    "SourceRoot",
    "apply",
    "build",
    "choose",
    "decide",
    "detect_entry_points",
    "expand_targets",
    "is_inferred",
    "link",
    "matched_symbols",
    "mentioned_symbols",
    "search",
]
