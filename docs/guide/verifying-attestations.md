# Verifying attestations

Two directions, and both matter.

**Ours about us:** can you check that the `vexpath` you installed was built
from this source by this workflow? A supply-chain tool whose own releases
cannot be verified is making an argument against itself.

**Ours about you:** `vexpath attest sign` produces a signed statement about
your SBOM or your VEX document. This is what a reviewer does with it.

## Verifying a vexpath release

```bash
# The distributions, against the provenance produced by the official
# SLSA generator.
slsa-verifier verify-artifact vexpath-0.1.0-py3-none-any.whl \
  --provenance-path vexpath-0.1.0-py3-none-any.whl.intoto.jsonl \
  --source-uri github.com/Unknown122-coder/vexpath \
  --source-tag v0.1.0

# The container image.
gh attestation verify oci://ghcr.io/unknown122-coder/vexpath:0.1.0 \
  --repo Unknown122-coder/vexpath
```

PyPI also shows its own attestation under each file on the project page,
because the release is published with Trusted Publishing — there is no API
token anywhere in the repository, so there is no token to steal and publish
with.

The `--source-tag` is the part that matters. A valid signature on its own says
only that *somebody* signed something; the useful question is whether **this
source, at this tag, built this artefact**.

## Verifying a statement vexpath produced

### With a key

```bash
vexpath attest verify vex.intoto.jsonl --key public.pem
```

### Keyless, from a CI identity

```bash
vexpath attest verify vex.intoto.jsonl \
  --expect-type vex \
  --expect-subject sha256:<digest of the document> \
  --expect-identity 'https://github.com/acme/api/.github/workflows/ci.yml@refs/heads/main' \
  --expect-issuer 'https://token.actions.githubusercontent.com'
```

**Rekor inclusion proofs and full keyless verification are not implemented
yet** — see [limitations](limitations.md). Until they are, verify a keyless
signature with `cosign verify-attestation`, which does check the transparency
log:

```bash
cosign verify-attestation \
  --type https://openvex.dev/ns/v0.2.0 \
  --certificate-identity-regexp 'https://github.com/acme/api/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vex.intoto.jsonl
```

## The three things worth checking, and why

**1. There is a subject, and it is the document you hold.** A statement with
no subject cannot be tied to anything; a verifier that ignores the subject
will happily accept a signature over somebody else's document. `--expect-subject`
takes the digest.

**2. The payload *type* is the one you expected.** The DSSE
pre-authentication encoding binds the payload type into the signed bytes,
which is what stops a signed VEX document being presented as a signed SBOM.
`--expect-type` asserts it rather than trusting the envelope's own label. (Our
implementation of that encoding is tested against the DSSE specification's own
example rather than against its own output, because a self-consistent
implementation of a wire format is the easiest kind to get wrong.)

**3. The identity, not just the signature.** "Valid signature" is a much
weaker fact than it sounds. The question is *whose*: which workflow, in which
repository, on which branch. `--expect-identity` and `--expect-issuer` are how
you say so, and the output names which constraints were actually applied — so
a verification that checked nothing cannot look like one that checked
everything.

## What a vexpath VEX statement says

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [{
    "vulnerability": {"name": "CVE-2026-1234"},
    "products": [{
      "@id": "pkg:generic/acme/api@1.4.0",
      "subcomponents": [{"@id": "pkg:pypi/jinja2@3.1.0"}]
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "impact_statement": "no path from any of 28 entry points reaches jinja2.sandbox..."
  }]
}
```

Three things to notice, because they are what most tools get wrong:

- **The product is your product.** The vulnerable dependency is a
  *subcomponent*. A VEX statement whose product is the dependency says
  something true and useless: that jinja2 has a vulnerability.
- **The only justification reachability earns is
  `vulnerable_code_not_in_execute_path`.** Generating any other from a
  reachability result raises rather than guessing, because a justification is
  a claim about *why*, and the wrong why is worse than none.
- **Every statement carries its evidence** in the impact statement. An
  unexplained clearance is one nobody can check, and "we removed 28 of your 38
  findings" is exactly the claim that needs checking.

In CycloneDX VEX the equivalent is `code_not_reachable`. `false_positive` is
never produced: a finding that does not apply because the code cannot run is
not a mistake in the advisory.

## Attesting your own scan, in CI

```yaml
permissions:
  contents: read
  id-token: write      # the signature is the workflow's own identity

steps:
  - uses: Unknown122-coder/vexpath@v1
    with:
      policy: balanced
      sign: true
```

Keyless, so there is no key to provision, rotate or leak — and the signature
says which workflow in which repository produced the document, which is a more
useful fact than "someone with the key signed it".
