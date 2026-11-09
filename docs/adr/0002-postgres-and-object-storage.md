# ADR-0002 · Postgres as the only database; S3-compatible object storage for artefacts

## Context
Data is relational (orgs → projects → scans → findings → advisories) with a need for transactional integrity, row-level security for multi-tenancy, and JSONB for semi-structured advisory payloads. Large blobs (SBOMs, VEX documents, call graphs, DSSE envelopes) are write-once and read by key. Free-tier hosting is a constraint (Neon 0.5 GB; R2 10 GB).

## Decision
- Postgres 16 holds all structured data, including the normalised advisory corpus and the job queue (ADR-0003). Row-level security enforces tenant isolation.
- Blobs go to S3-compatible object storage: Cloudflare R2 in production (no egress fees, which matters for call-graph downloads by CLIs).
- The local emulator is **undecided**. MinIO was the obvious choice, but its container images are no longer publicly pullable, so a local stack built on them does not start. Nothing writes an artefact before M3, so the decision is deferred to that milestone; the candidates are SeaweedFS, Garage, LocalStack, and a filesystem-backed implementation of the `ObjectStore` protocol for development only.
- No search engine, no graph database, no Redis in v1.

## Consequences
- Advisory full-text search is Postgres `tsvector`; adequate for package pages.
- Call-graph *search* happens in the CLI/worker process memory, not in the database; the database only indexes cached graphs.
- If the advisory corpus for all OSV ecosystems outgrows the free tier, we restrict synced ecosystems to those used by registered projects, then upgrade the tier.
