# 07 · Standards and Specifications Implemented

Exact versions we target. When a newer version ships, upgrading is an ADR, not a drive-by.

| Area | Standard | Version | How we use it |
|---|---|---|---|
| Package identity | Package URL (purl) | spec as of 2025, `packageurl-python` | Canonical component key; PyPI names PEP 503-normalised, npm scoped names percent-encoded |
| SBOM | CycloneDX | 1.6 JSON and XML (read, write); read 1.4/1.5 | Primary SBOM format; `metadata.component`, `components[]`, `dependencies[]`, `vulnerabilities[]` for CDX-VEX |
| SBOM | SPDX | 2.2 and 2.3 JSON and tag-value (read, write) | Secondary; `DEPENDS_ON`, `CONTAINS` and `HAS_PREREQUISITE` relationships, and their inverses, become dependency edges. Identity comes from the `purl` external reference. |
| SBOM baseline | CISA/NTIA Minimum Elements for an SBOM | 2021, with 2025 revision tracked | `vexpath sbom validate` reports gaps: supplier, component name, version, unique ids, dependency relationships, author, timestamp |
| Vulnerability data | OSV schema | 1.6.x | Source of truth for advisories and affected ranges; `ecosystem_specific` consumed where populated |
| Vulnerability data | GitHub Security Advisories (GraphQL) | current | Review state, CVSS 4.0, PR/commit references |
| Vulnerability data | FIRST EPSS | v3 daily CSV | Exploit probability on findings |
| Vulnerability data | CISA KEV | JSON feed | `kev` flag |
| Severity | CVSS | 3.0 and 3.1 scored; 4.0 carried | Base scores are **computed from the vector** by `core.cvss`, not read from a numeric field, because upstream data does not always keep the two consistent. CVSS 4.0 base scores come from a lookup table rather than a formula, so a 4.0 vector is carried unscored and its qualitative label is taken from the advisory. |
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
| Repo config | `.vexpath.yml` | our schema v1 | Documented in `04-api-and-cli.md` |

## Validation: what is checked against a schema, and what is not

**CycloneDX documents are validated against the official JSON schemas**, which
ship inside `cyclonedx-python-lib`. A document this project accepts or emits is
one the wider ecosystem accepts.

**SPDX documents are checked structurally only**, against the fields SPDX 2.3
requires, not against the official JSON schema. The CycloneDX schemas cost
nothing because they already ship with a dependency; bundling a copy of the
SPDX schema would mean maintaining a second source of truth for a
specification this project does not own. The structural checks catch the
mistakes that affect analysis: a missing version, a missing identifier, a
malformed relationship. Stating the limit here is the point.

## Where we extend standards (documented extensions)

1. **OpenVEX `impact_statement` structure.** The spec takes free text. We write human-readable text and additionally attach a CycloneDX-style `properties` block in the CDX-VEX output with `vexpath:reach.status`, `vexpath:reach.confidence`, `vexpath:reach.symbols`, `vexpath:reach.path` so machines can consume evidence.
2. **Vulnerable symbols.** No standard exists. Our `vulnerable_symbols` export format is JSON Lines with `{advisory, ecosystem, package, symbol, kind, source, fix_commit, confidence}` and is published under a permissive licence so others can consume or contribute.
3. **Results schema** `vexpath.results/1` (see `04-api-and-cli.md § 4`).
4. **Scope and directness in CycloneDX.** CycloneDX has no development scope,
   collapsing it to `optional`, and no way to say whether a component is a
   direct dependency. Both change what a policy decides, so they are carried
   as the properties `vexpath:scope` and `vexpath:direct`, and read back in
   preference to the standard field. Inventory limitations travel as
   `vexpath:note` properties, so a consumer holding only the document still
   learns what it could not determine.
