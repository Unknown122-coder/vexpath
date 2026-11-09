# Security policy

This project analyses untrusted input and publishes claims about other people's software. Both make it a worthwhile target, so its own security is treated as part of the product rather than an afterthought. The full analysis is in [docs/06-threat-model.md](docs/06-threat-model.md).

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button on the Security tab of this repository, which opens a private advisory visible only to the maintainers.

Please do not open a public issue for a security problem, and please do not include a working exploit in the first message. A description of the class of problem and the affected component is enough to start.

What to expect:

| Stage | Target |
|---|---|
| Acknowledgement that the report was received | 3 working days |
| Initial assessment, including whether it is in scope | 10 working days |
| Fix or a documented mitigation | 90 days from acknowledgement |

Credit is given in the advisory unless the reporter asks otherwise.

## In scope

- Remote code execution, command injection or path traversal reachable from any analysed input: an SBOM document, a lockfile, a repository, a package archive, or an advisory feed.
- Cross-tenant data access: any route by which one organisation can read or write another's projects, scans, findings or artefacts.
- Authentication or session flaws, API key handling, and privilege escalation between the owner and member roles.
- Forging a verdict: any way to make the platform publish, serve or attest a `not_affected` claim that the analysis did not actually produce, or to make a badge or public report page misrepresent a scan.
- Signature or attestation verification bypass.
- Server-side request forgery through a repository URL, an advisory reference, or any other fetched location.

## Specifically interesting

Two classes of bug matter more here than they would in most applications:

1. **A false `not_affected`.** The product's central promise is that only proven unreachability clears a finding. A way to produce a cleared verdict from uncertain analysis is a security issue, not merely a correctness one, because people will ship on the strength of it.
2. **Executing analysed code.** All analysis is static, by design. Any input that causes the analyser to execute code from an analysed project or package is a serious finding, however it is reached.

## Out of scope

- Reachability results that are wrong in the conservative direction. Reporting something reachable when it is not is a precision problem; file it as a normal issue with a reproducer.
- Missing findings caused by upstream advisory data being absent or wrong. Report those to the advisory source.
- Denial of service through deliberately enormous input, where the only effect is that the submitter's own scan is slow or rejected.
- Findings that require a compromised developer machine or a stolen API key to exploit.
- Reports from automated scanners with no demonstrated impact.

## Supported versions

Until the first tagged release, only the `main` branch is supported. After that, the latest minor release receives security fixes.

## Our own supply chain

This project runs its own analysis against itself in CI, pins its dependencies by hash through `uv.lock`, publishes build provenance for releases, and signs its own artefacts with Sigstore. A tool that asks people to trust its claims about dependencies should be able to show the same evidence about its own.
