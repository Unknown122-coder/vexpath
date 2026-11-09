# Architecture Decision Records

Format: context, decision, consequences. Status is `accepted` unless stated. Supersede with a new ADR rather than editing an old one.

| # | Decision |
|---|---|
| [0001](0001-python-fastapi-core.md) | Python 3.12 for the analysis core; FastAPI for the API |
| [0002](0002-postgres-and-object-storage.md) | Postgres as the only database; S3-compatible object storage for artefacts |
| [0003](0003-postgres-backed-queue.md) | Postgres-backed job queue instead of a broker |
| [0004](0004-nextjs-on-vercel.md) | ~~Next.js on Vercel for the web app and public pages~~ (superseded by 0011) |
| [0005](0005-cel-for-policy.md) | CEL for policy expressions |
| [0006](0006-sigstore-intoto-attestations.md) | Sigstore keyless signing of in-toto statements |
| [0007](0007-openvex-primary.md) | OpenVEX as the primary VEX format, CycloneDX VEX secondary |
| [0008](0008-own-python-callgraph-builder.md) | Build our own Python call-graph builder |
| [0009](0009-native-lockfile-sbom-generation.md) | Native lockfile-based SBOM generation with Syft as fallback |
| [0010](0010-local-first-analysis.md) | Local/CI analysis is the primary mode; hosted scanning is secondary |
| [0011](0011-server-rendered-python-web.md) | Server-rendered Python web UI inside the API application (supersedes 0004) |
| [0012](0012-python-only-reachability.md) | Python is the only reachability ecosystem in v1 |
| [0013](0013-the-name-vexpath.md) | The name is `vexpath` |
