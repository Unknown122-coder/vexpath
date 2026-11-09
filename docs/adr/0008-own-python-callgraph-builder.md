# ADR-0008 · Build our own Python call-graph builder

## Context
Existing options: PyCG (research tool, unmaintained, crashes on large codebases, no package-version cache), Jarviscg (research fork), code2flow (visualisation-oriented, imprecise), Pyan (abandoned), commercial engines (closed). None offer: deterministic output, a serialisable per-package graph that can be cached and linked at scan time, explicit conservative edges with provenance, and framework entry-point detection.

## Decision
Write `core.reach.python` ourselves on stdlib `ast`:
- Two-level design: per-package graphs with external call sites as unresolved references; link-time resolution against lockfile versions.
- Light flow-insensitive inference for assignments, `self` attributes, constructor returns; class-hierarchy analysis for method dispatch.
- Explicit `dynamic` and `opaque` markers that flow into confidence.
- Serialisation to msgpack with interned symbols; `builder_version` stamps for cache invalidation.

We borrow design ideas from PyCG's paper (assignment graph, iterative fix-point) but not its code.

## Consequences
- Significant engineering investment (this is most of M2), justified because it is the product's differentiator.
- We own the precision/recall trade-offs and can tune them with the benchmark.
- The two-level design keeps the linking and search layers language-neutral, so a future ecosystem needs only a new builder (ADR-0012).
