# ADR-0006 · Sigstore keyless signing of in-toto statements

## Context
Regulators and downstream consumers need to verify that a VEX document was produced by a specific party and not altered. Managing long-lived signing keys is error-prone and the first thing that gets leaked. Sigstore provides keyless signing bound to OIDC identities (GitHub Actions workflow, Google/GitHub/Microsoft accounts) with a public transparency log, and is what the ecosystem (npm provenance, PyPI attestations, SLSA) already uses.

## Decision
- Attestations are in-toto Statement v1 wrapped in DSSE, predicate types for CycloneDX and OpenVEX.
- Signing uses `sigstore-python` against the public-good instance. In CI: ambient OIDC. Locally: interactive OIDC, labelled as developer-signed.
- Verification requires certificate identity and issuer constraints; the platform re-verifies on ingest and displays the result.
- A `--key` option exists for organisations that cannot use the public instance (air-gapped), with no Rekor entry; such attestations are labelled accordingly.

## Consequences
- Dependency on Sigstore availability for signing; scans still complete and policy can require signing.
- Identity is public in Rekor; documented clearly for users who care.
- `cosign verify-attestation` works out of the box, which is a strong trust signal for the project.
