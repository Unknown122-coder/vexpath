# sscp-core

The analysis core. Everything that decides a verdict lives here, and nothing here imports a web framework or a database driver.

The same code runs in three places: the `sscp` CLI on a developer machine, the GitHub Action in CI, and the platform's sandboxed workers. That is deliberate (see `docs/adr/0010-local-first-analysis.md`): a verdict must not depend on where it was computed.

## Sub-packages

| Module | Scope | Milestone |
|---|---|---|
| `models` | Pydantic domain models shared by the CLI, API and database | M0 |
| `ids` | ULID generation | M0 |
| `purl` | Package URL construction and ecosystem-aware name normalisation | M0 |
| `enums` | Every closed vocabulary: verdicts, statuses, confidence, justifications | M0 |
| `protocols` | Interfaces injected into analysis (advisory source, clock, object store) so the core stays deterministic and offline-testable | M0 |
| `sbom` | Parse, validate, normalise and generate SBOMs | M1 |
| `advisory` | Advisory ingest, normalisation, snapshots and local cache | M1 |
| `vulnmatch` | Version-range matching of components against advisories | M1 |
| `reach` | Call-graph construction and reachability search | M2 |
| `vex` | OpenVEX and CycloneDX VEX generation | M3 |
| `attest` | in-toto statements, DSSE, Sigstore signing and verification | M3 |
| `policy` | CEL policy evaluation | M3 |
| `report` | Terminal, Markdown, HTML and SARIF rendering | M1, extended later |

## Rules this package follows

1. **Deterministic.** Time, network and storage arrive through `protocols`. Given the same inputs and the same advisory snapshot, the output is byte-identical.
2. **No execution of analysed code.** Parsing only, always.
3. **Strictly typed.** `mypy --strict` passes with no ignores outside the declared third-party overrides.
4. **No imports from `apps/`.**
