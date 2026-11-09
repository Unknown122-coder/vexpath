# ADR-0010 · Local/CI analysis is the primary mode; hosted scanning is secondary

## Context
Hosted scanning requires cloning customer source code into our infrastructure, which raises the security bar (sandboxing, secrets handling, data residency) and the cost (compute per scan). Teams that care about supply-chain security are the same teams that dislike shipping their source to a third party. The analysis core is deterministic and self-contained, so it runs equally well in the user's CI.

## Decision
- The CLI and the GitHub Action are the primary interface. All analysis happens where the code already is.
- The platform receives *results*: SBOM, findings, VEX, attestation, evidence paths, first-party graph statistics. Source code is never uploaded.
- Hosted scanning exists for the public demo (paste a public GitHub URL) and for teams that opt in, and reuses the exact same core in a sandboxed worker.
- Trust in uploaded results comes from attestations verified server-side, not from the platform having run the scan.

## Consequences
- The hosted platform can launch on free-tier compute because heavy work happens in users' CI.
- Verdicts can be recomputed server-side when new advisories land only if the user opted to upload the first-party call graph (an explicit setting, off by default); otherwise the platform flags "re-scan recommended".
- Feature parity between CLI and hosted mode is automatic.
