# 08 · Glossary

**Advisory** – A record describing a vulnerability in a package: identifiers, affected version ranges, severity, references. We normalise OSV and GHSA records into one.

**Affected range** – The set of versions of a package to which an advisory applies, expressed as OSV events (`introduced`, `fixed`, `last_affected`).

**Attestation** – A signed statement, in in-toto format, that binds a predicate (here: an SBOM or a VEX document) to a subject (the artefact's digest) and to the identity that produced it.

**Call graph** – A directed graph whose nodes are functions/methods/modules and whose edges mean "may call". We build one for first-party code and one per dependency version, then link them.

**CEL** – Common Expression Language. A small, non-Turing-complete expression language we use for policies.

**Conservative edge** – A call-graph edge added when the callee could not be resolved precisely, so that reachability errs toward "reachable".

**CRA** – EU Cyber Resilience Act. Requires manufacturers of products with digital elements to manage vulnerabilities and maintain SBOMs.

**CycloneDX** – An OWASP SBOM standard. Also defines a VEX profile.

**DSSE** – Dead Simple Signing Envelope. The wrapper format Sigstore and in-toto use for signed payloads.

**Entry point** – A symbol from which program execution can begin: CLI script, web route, task handler, `__main__`.

**EPSS** – Exploit Prediction Scoring System. Daily probability that a CVE is exploited in the wild within 30 days.

**Finding** – One (component, advisory) pair in a scan, plus the verdict and evidence.

**Fix commit** – The upstream commit that remediated an advisory. Its diff defines the vulnerable symbols.

**GHSA** – GitHub Security Advisory. Both an identifier scheme and a database.

**in-toto** – A framework for attestations about the software supply chain.

**KEV** – CISA Known Exploited Vulnerabilities catalogue.

**Keyless signing** – Sigstore's model: a short-lived certificate from Fulcio binds an OIDC identity to an ephemeral key; the signature is logged in Rekor.

**Opaque function** – A function containing `eval`, `exec`, `getattr` with non-literal names, or dynamic imports; treated as potentially calling anything it can see.

**OpenVEX** – A minimal VEX format maintained under the OpenSSF.

**OSV** – Open Source Vulnerabilities. Google-run aggregated vulnerability database and schema.

**Policy** – A CEL expression over findings that decides whether a build passes.

**purl** – Package URL. A URI scheme identifying a package in an ecosystem: `pkg:pypi/requests@2.31.0`.

**Reachability** – Whether vulnerable code can execute from the application's entry points.

**Rekor** – Sigstore's transparency log.

**RLS** – Row-level security in Postgres; used for tenant isolation.

**SARIF** – Static Analysis Results Interchange Format; consumed by GitHub Code Scanning.

**SBOM** – Software Bill of Materials: an inventory of components in a piece of software with their relationships.

**SLSA** – Supply-chain Levels for Software Artifacts; a framework for build provenance.

**Snapshot (advisory)** – An immutable, hashed version of the advisory corpus, recorded per scan for reproducibility.

**SPDX** – Linux Foundation SBOM standard.

**Suppression** – A manual, time-boxed decision to exclude a finding from policy, with a mandatory reason. Does not alter the analytical verdict.

**Symbol** – A fully qualified name of a function, method, class or module.

**Verdict** – Our conclusion for a finding: `affected`, `not_affected`, `under_investigation`, `fixed`. Mirrors OpenVEX statuses.

**VEX** – Vulnerability Exploitability eXchange: a machine-readable statement of whether a product is affected by a vulnerability and why.

**Vulnerable symbol** – A symbol modified by an advisory's fix commit; the target set for reachability search.
