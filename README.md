# Software Supply-Chain Security Platform

An open platform that turns a Software Bill of Materials (SBOM) into an honest answer to one question: **of all the known vulnerabilities in my dependencies, which ones can actually hurt me?**

It ingests SBOMs (CycloneDX, SPDX) or generates them from a repository, matches every component against public advisory databases, then performs **reachability analysis**: it builds a call graph of the user's code and its dependencies, extracts the exact functions that each advisory's fix commit touched, and checks whether those functions are reachable from the application's entry points. The result is published as a signed **OpenVEX** document and an **in-toto attestation**, enforced in CI by a **policy engine**, and surfaced on a hosted web platform with public report pages, per-package vulnerability pages and a README badge.

> Status: **M1 complete, M2 in progress** (2026-11-09). The scanner reads
> seven lockfile formats and both SBOM standards, matches against a
> reproducible advisory corpus, and reports in table, JSON, Markdown and
> SARIF. Reachability analysis runs as part of `vexpath scan`: it graphs the
> project and its installed dependencies, searches for each advisory's
> vulnerable symbols, and clears a finding only when no path reaches them.
> Symbols come from the advisory's fix commit, extracted by a worker that
> crawls upstream repositories, and `vexpath reach` explains any single verdict
> in full. Measured over 150 real PyPI advisories: 1,411 symbols from 106 of
> them. What remains in this milestone is the benchmark over 30 real
> repositories and enrichment from EPSS and CISA KEV. See
> [docs/05-roadmap.md](docs/05-roadmap.md).

## Quick start

```bash
make install                       # create the virtualenv and install every workspace member
make check                         # lint, type-check and run the unit tests

# Scan something, offline and reproducibly, against the committed test corpus.
export VEXPATH_ADVISORY_SNAPSHOT_DIR=testdata/advisories
uv run vexpath scan testdata/repos/direct-call

# Or download a current corpus first, then scan your own project.
uv run vexpath advisory sync var/advisories
uv run vexpath scan . --snapshot var/advisories

# Disagree with a verdict? Make it show its work, one advisory at a time.
uv run vexpath reach . --advisory CVE-2024-35195 --snapshot var/advisories

make up                            # Postgres, migrations, API and seeded advisories
curl localhost:8000/healthz

# The corpus a scan really wants: downloaded, then enriched with the symbols
# each advisory's fix commit changed. OSV does not publish those.
uv run python -m vexpath_worker.main sync-advisories var/corpus --ecosystem PyPI
uv run python -m vexpath_worker.main extract-symbols --batch 500 --cache-root var/repo-cache
uv run python -m vexpath_worker.main export-snapshot var/enriched --ecosystem PyPI
uv run vexpath scan . --snapshot var/enriched
```

Extraction is a long crawl, and it is built to be stopped: every advisory's
outcome is committed as it is decided, so run it repeatedly until the backlog
stops shrinking. Nothing it fetches is ever executed.

What a scan says, and what it refuses to say. A finding is cleared only when
the analysis traversed the dependency's own code and found no path to the
functions the fix changed. Everything else is reported. In particular a
dependency whose source could not be read is **under investigation**, never
cleared: a direct call to a vulnerable symbol is still visible, so "reachable"
stays sound, but an absence of paths through code nobody looked at proves
nothing.

Reachability needs the dependencies on disk. By default it reads the
environment the command is running in; point it elsewhere with
`--environment path/to/.venv`, and tell it how the application starts with
`--entry-point mypackage.cli:main`, which beats any inference. `--no-reach`
reports matching alone and says so in the output.

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
│   └── cli/            The `vexpath` command-line tool, built on core
├── infra/              Dockerfile, Docker Compose, Alembic config, deployment manifests
├── tools/              Developer scripts
├── docs/               This blueprint
└── testdata/           Frozen advisory snapshot, fixture SBOMs, six fixture repositories
```

The name is settled and recorded in [ADR-0013](docs/adr/0013-the-name-vexpath.md):
**VEX** is the signed exploitability document this tool emits, and **path** is
the call path that is the evidence behind every verdict.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

Apache 2.0 rather than MIT for the patent grant in section 3. A tool that
analyses other people's dependencies and publishes signed claims about them
will be adopted by companies whose legal review asks about patents, and the
explicit grant removes that question. Per-file licence headers are not used;
the LICENSE file governs the whole repository.
