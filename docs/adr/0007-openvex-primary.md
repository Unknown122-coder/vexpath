# ADR-0007 · OpenVEX as the primary VEX format, CycloneDX VEX secondary

## Context
Three VEX formats exist: CSAF VEX (heavyweight, publisher-oriented), CycloneDX VEX (embedded in or alongside a CycloneDX BOM), OpenVEX (minimal, purpose-built, OpenSSF). Our statements are per product-version, per vulnerability, with justification and impact text, exactly OpenVEX's shape. Many SBOM consumers, however, expect CycloneDX.

## Decision
- OpenVEX 0.2.0 is the canonical output; one document per scan, one statement per finding.
- CycloneDX VEX is generated from the same internal model for consumers that want a single CycloneDX bundle.
- CSAF is out of scope for v1; the internal model keeps the fields CSAF would need (product tree, notes) so an exporter can be added.

## Consequences
- Two serialisers to keep in sync; tests assert equivalence of statuses between them.
- Evidence (symbols, paths) does not fit OpenVEX's schema and is carried in the impact statement text plus a documented extension in the CDX output (`07-standards.md`).
