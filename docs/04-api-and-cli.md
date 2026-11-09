# 04 · API, CLI and GitHub Action Interfaces

## 1. CLI: `vexpath`

Installed with `pipx install vexpath` or `uv tool install vexpath`. All commands accept `--format table|json|markdown|sarif` and `--quiet`. Exit codes: `0` ok, `1` policy failed, `2` analysis error, `3` configuration error.

| Command | Purpose |
|---|---|
| `vexpath sbom generate [PATH] [-o sbom.cdx.json] [--format cyclonedx\|spdx]` | Generate an SBOM from lockfiles (native) or via Syft (`--syft`) |
| `vexpath sbom validate FILE` | Schema-validate a CycloneDX/SPDX document; report CISA minimum-elements gaps |
| `vexpath scan [PATH] [--sbom FILE] [--no-reach] [--policy FILE\|preset] [--upload] [--sign]` | Full pipeline: SBOM → match → reachability → VEX → policy. The default command. |
| `vexpath reach [PATH] --advisory CVE-… [--symbol …]` | Reachability for one advisory; prints all paths. Debugging and triage. |
| `vexpath vex export [--format openvex\|cyclonedx] [-o FILE]` | Write VEX for the last scan |
| `vexpath attest sign FILE --type sbom\|vex` | Produce a signed in-toto statement (keyless by default; `--key` for a static key) |
| `vexpath attest verify FILE --identity … --issuer …` | Verify a DSSE envelope against Rekor and identity constraints |
| `vexpath policy test POLICY [--scan results.json]` | Evaluate a CEL policy against scan output without rescanning |
| `vexpath advisory show CVE-…` | Advisory details, affected ranges, extracted vulnerable symbols with confidence |
| `vexpath advisory sync [--ecosystem PyPI,npm] [--dir ~/.cache/vexpath]` | Download a local advisory snapshot for offline/air-gapped use |
| `vexpath callgraph build PATH` / `vexpath callgraph show SYMBOL` | Build/inspect graphs; used in development and support |
| `vexpath login` / `vexpath whoami` | Store an API key for uploads |

### `.vexpath.yml`

```yaml
version: 1
project: my-org/my-service          # platform project slug, optional
entry_points:                       # optional; dotted symbols or globs
  - app.main:create_app
  - "app/cli/*.py"
ignore_paths: ["migrations/", "scripts/legacy/"]
policy: balanced                    # preset name or path to a .cel file
reachability:
  enabled: true
  treat_dev_scope: ignore           # ignore | analyze | block
  fallback_entry_points: public     # public | none (fail if no entry points found)
upload: on_ci                       # always | on_ci | never
sign: on_ci
```

### Policy presets (CEL)

```cel
// strict
findings.exists(f, f.verdict == "affected" && f.severity in ["CRITICAL", "HIGH"])

// balanced (default)
findings.exists(f,
  f.verdict == "affected" && f.reach.status == "reachable_confirmed" && f.severity in ["CRITICAL", "HIGH"]
) || findings.exists(f, f.kev && f.verdict != "not_affected")

// kev-only
findings.exists(f, f.kev && f.verdict != "not_affected")
```

A policy expression evaluates to `true` when the build must **fail**. The evaluation context exposes `findings[]` (each with `advisory`, `component`, `severity`, `cvss`, `epss`, `kev`, `verdict`, `justification`, `reach{status, reason, confidence}`, `fixed_in`, `age_days`, `scope`, `direct`), `scan{mode, git_ref}`, and `project{slug}`.

Reachability analysis covers Python components only (ADR-0012). Components from other ecosystems carry `reach.status == "symbols_unknown"` with `reach.reason == "ecosystem_unsupported"`, and the report prints a capability note beside them. Policies that want to gate on those explicitly can test that reason.

## 2. GitHub Action: `apps/action`

```yaml
- uses: <org>/vexpath-action@v1
  with:
    policy: balanced              # preset, path, or inline CEL
    upload: true                  # requires VEXPATH_API_KEY secret (or GitHub App)
    sign: true                    # keyless via the job's OIDC token; needs id-token: write
    sarif: true                   # upload to Code Scanning for inline annotations
    comment: on-change            # always | on-change | never — PR comment with diff
    sbom-path: ""                 # use an existing SBOM instead of generating
  env:
    VEXPATH_API_KEY: ${{ secrets.VEXPATH_API_KEY }}
```

Outputs: `verdict-summary` (JSON), `vex-path`, `attestation-path`, `report-url`.

Permissions required: `contents: read`, `id-token: write` (signing), `security-events: write` (SARIF), `pull-requests: write` (comment).

## 3. REST API: `apps/api`

Base URL `https://api.<domain>/v1`. JSON everywhere; problem details (RFC 9457) for errors. Authentication by `Authorization: Bearer vexpath_live_…` or session cookie. Rate limits: 60 requests/minute per key for writes, 600 for reads; unauthenticated badge and public endpoints are edge-cached.

### Projects and scans

| Method | Path | Notes |
|---|---|---|
| `GET` | `/projects` | List projects in the caller's org |
| `POST` | `/projects` | `{slug, repo_url, visibility}` |
| `GET` | `/projects/{slug}` | |
| `PATCH` | `/projects/{slug}` | visibility, entry points, settings |
| `POST` | `/projects/{slug}/scans` | Upload a completed CLI scan: multipart with `results.json`, `sbom`, `openvex.json`, optional `attestation.intoto.jsonl`. Returns `202` + scan id. |
| `POST` | `/projects/{slug}/scans/hosted` | `{git_ref}`; requires GitHub App installation. Enqueues `scan.hosted`. |
| `GET` | `/projects/{slug}/scans` | Paginated; filter by `git_ref`, `status` |
| `GET` | `/scans/{id}` | Summary, diff vs previous, links to artefacts |
| `GET` | `/scans/{id}/findings` | Filter by `verdict`, `severity`, `reach_status`; includes evidence paths |
| `GET` | `/scans/{id}/sbom` | Redirect to presigned object URL |
| `GET` | `/scans/{id}/vex?format=openvex\|cyclonedx` | |
| `GET` | `/scans/{id}/attestation` | DSSE envelope |
| `GET` | `/scans/{id}/policy` | Evaluation result |

### Findings and suppressions

| Method | Path | Notes |
|---|---|---|
| `GET` | `/findings/{id}` | Full detail including `reachability_result` and VEX statement |
| `POST` | `/projects/{slug}/suppressions` | `{advisory_id, component_purl?, justification, reason, expires_at}` |
| `DELETE` | `/suppressions/{id}` | |

### Advisory data (global, read-only)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/advisories/{id}` | Normalised advisory, affected ranges, vulnerable symbols |
| `POST` | `/advisories/query` | `{purls: [...]}` batched match; returns findings-shaped records with snapshot id. Used by the CLI. Max 2,000 purls per call. |
| `GET` | `/packages/{ecosystem}/{name}` | Package page data: advisory history, symbol coverage, public-project reach stats |
| `GET` | `/snapshots/{id}` | Snapshot metadata |
| `GET` | `/snapshots/latest/download?ecosystem=PyPI` | zstd JSONL for `vexpath advisory sync` |

### Call-graph cache (global)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/callgraphs/bundle` | `{packages: [{ecosystem, name, version}]}` → presigned URLs for ready graphs + list of misses (which the CLI builds locally and may `PUT` back if `contribute: true`) |
| `PUT` | `/callgraphs/{ecosystem}/{name}/{version}` | Contribute a locally built graph; server rebuilds and verifies hash before publishing (never trusts client output) |

### Public and badge

| Method | Path | Notes |
|---|---|---|
| `GET` | `/public/r/{org}/{project}` | Public report payload (only `visibility = public`) |
| `GET` | `/badge/{org}/{project}.svg?style=flat` | Shields-style SVG: `reachable vulns · 0` (green), `· 3 high` (red), `· unknown` (grey). `Cache-Control: max-age=300`, ETag. |
| `GET` | `/public/p/{ecosystem}/{name}` | Same as package page data, cached |

### Account

`GET /me`, `GET/POST/DELETE /api-keys`, `GET /orgs/{slug}/members`, `GET /orgs/{slug}/audit-log`.

### Webhooks (outbound)

Per project: `scan.completed`, `finding.new_reachable`, `advisory.updated_affecting_project` (a newly published advisory or newly extracted symbols change a verdict for the latest scan; the platform re-evaluates reachability against stored graphs without a new scan). HMAC-SHA256 signed payloads, retries with backoff.

## 4. Results JSON (CLI output, upload payload)

```json
{
  "schema": "vexpath.results/1",
  "core_version": "0.3.0",
  "advisory_snapshot_id": "01J…",
  "project": {"slug": "acme/api", "git_ref": "refs/heads/main", "git_sha": "…"},
  "sbom": {"format": "cyclonedx-1.6-json", "sha256": "…", "component_count": 412},
  "entry_points": {"source": "framework", "count": 14, "items": ["app.main:create_app", "…"]},
  "graph": {"first_party_nodes": 1842, "linked_packages": 398, "unresolved_call_ratio": 0.07},
  "findings": [
    {
      "id": "…",
      "advisory": {"id": "CVE-2024-35195", "severity": "HIGH", "cvss_v3": 5.6, "epss": 0.0012, "kev": false},
      "component": {"purl": "pkg:pypi/requests@2.31.0", "direct": true, "scope": "runtime"},
      "fixed_in": "2.32.0",
      "verdict": "affected",
      "justification": null,
      "reach": {
        "status": "reachable_confirmed",
        "reason": null,
        "confidence": "high",
        "matched_symbols": ["requests.adapters.HTTPAdapter.send"],
        "shortest_path": [
          {"symbol": "app.main.fetch_upstream", "file": "app/main.py", "line": 42},
          {"symbol": "requests.sessions.Session.get", "file": "requests/sessions.py", "line": 602},
          {"symbol": "requests.adapters.HTTPAdapter.send", "file": "requests/adapters.py", "line": 486}
        ],
        "path_count": 3,
        "via_dynamic_edges": false
      }
    }
  ],
  "policy": {"name": "balanced", "passed": false, "violations": ["…"]},
  "artifacts": {"openvex": "openvex.json", "cdx_vex": "cdx-vex.json", "attestation": "attestation.intoto.jsonl"}
}
```

This schema is versioned (`vexpath.results/1`) and published as JSON Schema in `packages/core/schemas/`.
