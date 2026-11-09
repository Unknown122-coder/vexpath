# 07 · Standards and Specifications Implemented

Exact versions we target. When a newer version ships, upgrading is an ADR, not a drive-by.

| Area | Standard | Version | How we use it |
|---|---|---|---|
| Package identity | Package URL (purl) | spec as of 2025, `packageurl-python` | Canonical component key; PyPI names PEP 503-normalised, npm scoped names percent-encoded |
| SBOM | CycloneDX | 1.6 JSON and XML (read, write); read 1.4/1.5 | Primary SBOM format; `metadata.component`, `components[]`, `dependencies[]`, `vulnerabilities[]` for CDX-VEX |
| SBOM | SPDX | 2.3 JSON and tag-value (read, write); 3.0.1 JSON-LD read-only | Secondary; map `relationships` DEPENDS_ON to our edges |
| SBOM baseline | CISA/NTIA Minimum Elements for an SBOM | 2021, with 2025 revision tracked | `sscp sbom validate` reports gaps: supplier, component name, version, unique ids, dependency relationships, author, timestamp |
| Vulnerability data | OSV schema | 1.6.x | Source of truth for advisories and affected ranges; `ecosystem_specific` consumed where populated |
| Vulnerability data | GitHub Security Advisories (GraphQL) | current | Review state, CVSS 4.0, PR/commit references |
| Vulnerability data | FIRST EPSS | v3 daily CSV | Exploit probability on findings |
| Vulnerability data | CISA KEV | JSON feed | `kev` flag |
| Severity | CVSS | 3.1 and 4.0 | Stored as vector + score; normalised label |
| Versioning | PEP 440, semver 2.0.0 | | Range evaluation with `packaging` and `semver`/node-semver semantics for npm |
| VEX | OpenVEX | 0.2.0 | Primary VEX output; statuses and justification labels exactly as the spec enumerates |
| VEX | CycloneDX VEX | 1.6 | `vulnerabilities[].analysis.state` mapping: `affected` → `exploitable`, `not_affected` → `not_affected` with `justification`, `under_investigation` → `in_triage`, `fixed` → `resolved` |
| Attestation | in-toto Attestation Framework | Statement v1 | Subjects are SBOM/VEX digests; predicate types `https://cyclonedx.org/bom` and `https://openvex.dev/ns/v0.2.0` |
| Envelope | DSSE | 1.0 | Signed envelope for statements |
| Signing | Sigstore (Fulcio, Rekor, cosign compatibility) | public-good instance; `sigstore-python` 3.x | Keyless signing with OIDC identities; bundle format v0.3 |
| Provenance (our own releases) | SLSA | v1.1 Build L3 via GitHub generator | Release provenance for the CLI and Action |
| Static results | SARIF | 2.1.0 | GitHub Code Scanning upload from the Action |
| Policy | CEL | language spec, `cel-python` | Policy expressions |
| API | OpenAPI | 3.1 | Generated from FastAPI, committed to repo |
| API errors | RFC 9457 Problem Details | | Error bodies |
| Identifiers | ULID | | Primary keys |
| Repo config | `.sscp.yml` | our schema v1 | Documented in `04-api-and-cli.md` |

## Where we extend standards (documented extensions)

1. **OpenVEX `impact_statement` structure.** The spec takes free text. We write human-readable text and additionally attach a CycloneDX-style `properties` block in the CDX-VEX output with `sscp:reach.status`, `sscp:reach.confidence`, `sscp:reach.symbols`, `sscp:reach.path` so machines can consume evidence.
2. **Vulnerable symbols.** No standard exists. Our `vulnerable_symbols` export format is JSON Lines with `{advisory, ecosystem, package, symbol, kind, source, fix_commit, confidence}` and is published under a permissive licence so others can consume or contribute.
3. **Results schema** `sscp.results/1` (see `04-api-and-cli.md § 4`).
