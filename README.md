# Software Supply-Chain Security Platform

An open platform that turns a Software Bill of Materials (SBOM) into an honest answer to one question: **of all the known vulnerabilities in my dependencies, which ones can actually hurt me?**

It ingests SBOMs (CycloneDX, SPDX) or generates them from a repository, matches every component against public advisory databases, then performs **reachability analysis**: it builds a call graph of the user's code and its dependencies, extracts the exact functions that each advisory's fix commit touched, and checks whether those functions are reachable from the application's entry points. The result is published as a signed **OpenVEX** document and an **in-toto attestation**, enforced in CI by a **policy engine**, and surfaced on a hosted web platform with public report pages, per-package vulnerability pages and a README badge.

> Status: **M0 complete** (2026-11-09). The repository, tooling, domain models, database schema, API skeleton and test fixtures are in place and green. Analysis itself starts at M1. See [docs/05-roadmap.md](docs/05-roadmap.md).

## Quick start

```bash
make install          # create the virtualenv and install every workspace member
make check            # lint, type-check and run the unit tests
make up               # Postgres, MinIO, migrations, API and seeded advisories
curl localhost:8000/healthz
```

`make help` lists every target. No Node, npm or bundler is involved anywhere (ADR-0011).

## Why this exists

- Dependency scanners report hundreds of CVEs per project; typically fewer than 10 % are exploitable in a given application. Teams drown in noise and stop looking.
- Regulation now demands SBOMs *and* a documented exploitability verdict: the EU Cyber Resilience Act, US federal procurement guidance, and FDA premarket cybersecurity requirements for medical devices.
- The commercial tools that do reachability analysis are expensive and closed. The open-source ecosystem has SBOM generators and scanners but no end-to-end open platform that produces defensible VEX.

## Documentation map

| Doc | What it answers |
|---|---|
| [docs/00-blueprint.md](docs/00-blueprint.md) | What we are building, for whom, what we are *not* building, and how we win |
| [docs/01-architecture.md](docs/01-architecture.md) | System components, data flows, deployment topology, repo layout |
| [docs/02-data-model.md](docs/02-data-model.md) | Database schema and core domain objects |
| [docs/03-reachability-design.md](docs/03-reachability-design.md) | The core algorithm: call graphs, patch diffing, verdicts and confidence |
| [docs/04-api-and-cli.md](docs/04-api-and-cli.md) | REST API surface, CLI commands, GitHub Action interface |
| [docs/05-roadmap.md](docs/05-roadmap.md) | Milestones with acceptance criteria |
| [docs/06-threat-model.md](docs/06-threat-model.md) | How a security tool stays secure itself |
| [docs/07-standards.md](docs/07-standards.md) | Every spec we implement and the exact versions |
| [docs/08-glossary.md](docs/08-glossary.md) | Terms used throughout |
| [docs/adr/](docs/adr/) | Architecture Decision Records |

## Planned repository layout (monorepo)

```
.
├── apps/
│   ├── api/            FastAPI service: /v1 JSON API and the server-rendered HTML UI
│   ├── worker/         Background jobs: advisory sync, patch diffing, call-graph builds
│   └── action/         GitHub Action wrapping the CLI (M5)
├── packages/
│   ├── core/           The analysis library. Decides verdicts. No framework, no database.
│   ├── platform/       Configuration and logging, shared by the API and the workers
│   ├── db/             SQLAlchemy schema, engine helpers and Alembic migrations
│   └── cli/            The `sscp` command-line tool, built on core
├── infra/              Dockerfile, Docker Compose, Alembic config, deployment manifests
├── tools/              Developer scripts
├── docs/               This blueprint
└── testdata/           Frozen advisory snapshot, fixture SBOMs, six fixture repositories
```

`sscp` is a placeholder command name until the product is named.
