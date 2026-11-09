# 00 · Product Blueprint

## 1. One-sentence pitch

Upload an SBOM or point us at a repository, and get back a signed, verifiable statement of which known vulnerabilities are actually reachable in your application, enforced in CI and published on a page you can link from your README.

## 2. The problem, concretely

A typical mid-size Python or JavaScript service has 300 to 1,500 transitive dependencies. Running any scanner (Trivy, Grype, Dependabot, Snyk free tier) against it produces 50 to 500 findings. Industry measurements from vendors that do reachability analysis consistently put the share of *exploitable* findings in a given application between 2 % and 10 %.

Three consequences:

1. **Alert fatigue.** Engineers learn that the scanner is noise and stop reading it. Real issues hide in the pile.
2. **Wasted upgrades.** Teams bump versions, break things and burn sprints on vulnerabilities in code paths their application never calls.
3. **No defensible paper trail.** When a customer or regulator asks "are you affected by CVE-2026-XXXXX?", the answer is a Slack thread, not a signed document.

Regulation has turned the third point from an annoyance into an obligation:

| Driver | What it requires | Timeline |
|---|---|---|
| EU Cyber Resilience Act (CRA) | Manufacturers of products with digital elements must maintain an SBOM, handle vulnerabilities, and report actively exploited ones | Reporting obligations from 11 Sep 2026; full application 11 Dec 2027 |
| US EO 14028 and successors, OMB M-22-18 / M-23-16 | SBOMs and secure-development attestations for software sold to federal agencies | In force |
| FDA Section 524B (FD&C Act) | Cyber-device premarket submissions must include an SBOM and a vulnerability management plan | Since March 2023 |
| CISA "Minimum Elements for an SBOM" (2021, revised draft 2025) | Defines required SBOM fields, including dependency relationships and known-unknowns | Reference baseline |
| NTIA / CISA VEX guidance, OpenVEX | Machine-readable exploitability statements to accompany SBOMs | Reference baseline |

The regulated world has to produce SBOMs **and** say which vulnerabilities in them matter. Almost no open tooling helps with the second half.

## 3. Who it is for (personas)

| Persona | Situation | What they need from us |
|---|---|---|
| **Backend / platform engineer** at a startup or mid-size company | Owns CI, drowning in Dependabot alerts | A CI step that fails only on *reachable* critical issues and explains why in the PR |
| **Security engineer / AppSec lead** | Has to answer "are we affected?" fast and keep an audit trail | Signed VEX documents, history of verdicts, policy they can tune |
| **Open-source maintainer** | Wants to show downstream users their package is clean, or that a CVE in a dependency is not exploitable through their library | Public report page and README badge |
| **Compliance / regulatory owner** (CRA, FDA, federal vendor) | Needs SBOM + VEX artefacts that survive an audit | Standards-conformant output, attestation signing, exportable evidence bundle |

Non-persona for v1: large enterprises needing on-prem deployment, SSO, and SLAs. The architecture must not *prevent* that, but we do not build for it first.

## 4. What we build (scope of v1)

### 4.1 Core capabilities

1. **SBOM ingest and generation**
   - Accept CycloneDX (JSON, XML) and SPDX (JSON, tag-value) documents. Validate against official schemas.
   - Generate SBOMs from Python projects natively (lockfiles: `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` with pinned versions, `pdm.lock`) and from npm projects (`package-lock.json`, `pnpm-lock.yaml`; pure JSON and YAML parsing in Python). Fall back to wrapping Syft for other ecosystems.
   - Every component gets a canonical Package URL (purl).

2. **Vulnerability matching**
   - Advisory sources: OSV.dev (primary; covers PyPI, npm, Go, crates, Maven, and GitHub Security Advisories), GitHub Advisory Database (for review state and CVSS), deps.dev (dependency graph enrichment, licenses, OpenSSF Scorecard).
   - Match by purl + semver / PEP 440 range evaluation, not by name fuzzing.
   - Deduplicate aliases (CVE, GHSA, PYSEC) into one advisory record.
   - Severity: CVSS 3.1 and 4.0 where present, EPSS score, CISA KEV flag.

3. **Reachability analysis** (the differentiator; see `03-reachability-design.md`)
   - Python only in v1 (ADR-0012). Other ecosystems get matching, VEX, attestation and policy, with every finding honestly reported as `under_investigation` rather than silently assumed safe.
   - For each advisory with a known fix commit, extract the set of functions/methods modified by the fix: the *vulnerable symbols*.
   - Build a static call graph of the user's repository plus the exact dependency versions from the lockfile.
   - Determine whether any vulnerable symbol is reachable from the application's entry points.
   - Emit a verdict with a confidence level and the shortest call path as evidence.

4. **VEX and attestation output**
   - OpenVEX document per scan with `affected`, `not_affected` (justification `vulnerable_code_not_in_execute_path` or `vulnerable_code_not_present`), `under_investigation`, `fixed`.
   - CycloneDX VEX (the `vulnerabilities` array with `analysis.state`) for consumers that prefer it.
   - in-toto Statement wrapping the SBOM and the VEX, signed keylessly with Sigstore (Fulcio certificate + Rekor transparency log) in CI; signed with a developer identity for local runs.
   - Verifiable by anyone with `cosign verify-attestation` or our CLI.

5. **Policy engine**
   - Policies written in CEL (Common Expression Language) evaluated against the findings set.
   - Built-in policy presets: `strict`, `balanced`, `kev-only`.
   - Example: `findings.exists(f, f.reachable == "confirmed" && f.severity >= "HIGH" && f.age_days > 14)` fails the build.
   - Output as GitHub Checks annotations and a PR comment.

6. **Hosted platform**
   - Accounts, organizations, projects, API keys.
   - Scan history with verdict diffs between commits ("this PR introduced 1 newly reachable HIGH").
   - Public report pages (opt-in), per-package pages, README badge (SVG endpoint).
   - Documentation site.

7. **Distribution**
   - `vexpath` CLI on PyPI.
   - GitHub Action on the Marketplace.
   - Docker image.

### 4.2 Explicit non-goals for v1

- No SAST for first-party code vulnerabilities (we analyse reachability *to* third-party vulnerable code; we do not hunt for new bugs).
- No container image or OS-package scanning beyond what the Syft wrapper provides.
- No secrets scanning, no license-compliance workflow (license *data* is shown; policy on it comes later).
- No dynamic/runtime instrumentation in v1 (designed for later: coverage upload as a reachability signal).
- No on-prem installer, SSO/SAML, or RBAC beyond owner/member.
- No ecosystems beyond Python for reachability (ADR-0012). Matching works for all OSV ecosystems.
- No JavaScript in the codebase: the web UI is server-rendered Python (ADR-0011) and there is no JavaScript call-graph builder.

## 5. How we are different

| | Dependabot / Renovate | Trivy / Grype | Snyk / Endor Labs / Semgrep Supply Chain | **This platform** |
|---|---|---|---|---|
| SBOM in/out | partial | yes | yes | yes, standards-validated |
| Reachability | no | no | yes (closed, paid) | **yes, open, with evidence paths** |
| VEX output | no | partial | partial | **OpenVEX + CycloneDX VEX, signed** |
| Attestations | no | no | some | **in-toto + Sigstore, verifiable by third parties** |
| Policy as code | no | basic | yes | **CEL, versioned with the repo** |
| Public proof (badge, report page) | no | no | no | **yes** |
| Cost | free | free | $$$ | free tier + open core |

The wedge is **open, evidence-backed reachability that produces regulator-grade documents**. Everything else is table stakes we must still get right.

## 6. Principles that shape every decision

1. **Never execute user code.** All analysis is static. Repository checkouts run in isolated workers with no network except to fetch declared dependencies.
2. **Every verdict carries evidence.** A `not_affected` must cite the vulnerable symbols and prove absence of a path. An `affected` must show the path. "Trust us" is not an output.
3. **Admit uncertainty.** When no fix commit exists or the call graph is incomplete, say `under_investigation` with a reason. A false "not affected" is the worst possible failure for this product.
4. **Standards over inventions.** purl, OSV schema, CycloneDX, SPDX, OpenVEX, in-toto, SLSA, Sigstore. We extend only where the standards are silent, and we document it.
5. **Deterministic and reproducible.** Same SBOM + same advisory snapshot = same output. Advisory data is versioned so a scan can be re-run against the snapshot it used.
6. **Free to run.** Every external data source has a free API or bulk export. The reference deployment fits on free tiers (see `01-architecture.md § 7`).

## 7. Success criteria for the project

Technical:
- On a benchmark set of 30 real Python repositories with 100+ known findings each, the reachability verdicts agree with manual review in at least 90 % of `confirmed`/`unreachable` cases, and there are **zero** cases of a manually confirmed exploitable CVE being marked `not_affected`.
- Full scan of a 500-dependency Python project completes in under 5 minutes on the free-tier worker with a warm call-graph cache.
- Attestations verify with stock `cosign` with no custom flags beyond the predicate type.

Product:
- GitHub Action published and used on at least three repositories outside the author's own.
- Public package pages indexed by search engines and receiving organic traffic.

## 8. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Fix commits missing or unparsable for many advisories | Reachability coverage too low to be useful | Measure coverage early (M1). Fall back to `under_investigation`. Add a community-curated symbol database (`vulnerable_symbols` overrides) and import from existing datasets where licence permits. |
| Python dynamic dispatch defeats static call graphs | False `unreachable` | Conservative resolution: unknown call targets are treated as potentially reaching any symbol in the same package; confidence tiers make this visible; policies can require `confirmed` only for *suppression*, never for *blocking*. |
| Advisory data volume and sync cost | Free-tier database limits | Sync only ecosystems in use (PyPI, npm first); keep normalised advisories, not raw blobs; cold storage for history. |
| Analysing untrusted repositories | RCE, SSRF, resource exhaustion | Static-only, sandboxed workers, no network during analysis, CPU/memory/time limits. See `06-threat-model.md`. |
| Scope creep into a general security suite | Never ships | The non-goals list above is binding until v1 is released. |
