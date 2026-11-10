# vexpath

**Most of your vulnerability findings cannot run.** vexpath works out which
ones can, and shows you the call path that proves it.

```bash
uv tool install vexpath      # or: pipx install vexpath
vexpath scan .
```

A scanner tells you that `jinja2` has a critical advisory. vexpath reads the
commit that fixed it, extracts the functions it changed, builds a call graph
from your code through your dependencies, and tells you whether anything you
run can reach them. On five real repositories it cleared 68 of 146 findings as
unreachable, with the evidence for each.

```
SEVERITY  VERDICT       ADVISORY         COMPONENT              REACHABILITY
--------------------------------------------------------------------------------
HIGH      affected      CVE-2026-1234    jinja2 3.1.0           reachable_confirmed
MEDIUM    not_affected  CVE-2026-5678    urllib3 2.2.1          unreachable

38 findings | 10 reachable | 28 not affected | 0 under investigation
```

## What makes a finding clearable

A finding is cleared only when the vulnerable code **provably** cannot run.
That requires the dependency's own source, so:

```bash
pip install -e .            # or uv sync, or poetry install
vexpath scan .
```

With nothing installed, vexpath still matches advisories but clears nothing —
an absence of paths through code it never read proves nothing, and it says so
rather than implying a clean bill of health. `--download-missing` fetches each
dependency's source from the package index instead (nothing is executed,
ever).

## The gate

```bash
vexpath scan . --policy balanced
```

Exits 1 when a critical or high finding's vulnerable code is provably
reachable, or when anything in your tree is in CISA's Known Exploited
Vulnerabilities catalogue. Five presets, or write your own in CEL:

```bash
vexpath policy list
vexpath scan . --policy 'findings.exists(f, f.kev && f.verdict != "not_affected")'
```

## Exit codes

The contract with CI, and fixed:

| Code | Meaning |
|---|---|
| 0 | Analysis completed and the policy passed |
| 1 | Analysis completed and the policy **failed** — your dependencies need attention |
| 2 | Analysis could not complete: a broken lockfile, an unreachable index |
| 3 | Configuration error: a policy that does not compile, a bad flag |

1 and 2 are separate on purpose. A build failing because the code is
vulnerable must never look like a build failing because the tool broke.

## What else it does

| Command | What for |
|---|---|
| `vexpath scan` | The whole pipeline: SBOM → match → reachability → VEX → gate |
| `vexpath reach --advisory CVE-…` | Why one verdict is what it is: symbols searched for, which entry points reach them, by what path, and the graph it rests on |
| `vexpath report results.json --format sarif` | Re-render a scan. Nothing is re-analysed, so the SARIF matches the table |
| `vexpath sbom generate` | CycloneDX 1.6 or SPDX 2.3 from seven lockfile formats |
| `vexpath vex export` | OpenVEX 0.2.0 or CycloneDX VEX, with the evidence attached |
| `vexpath attest sign` | A signed in-toto statement in a DSSE envelope, keyless or with a key |
| `vexpath advisory sync` | Download a local advisory snapshot for offline and air-gapped use |
| `vexpath policy test` | Try a gate against a scan that already ran |

## Offline and reproducible

```bash
vexpath advisory sync --ecosystem PyPI --dir ./advisories
vexpath scan . --snapshot ./advisories
```

A scan against a pinned snapshot can be re-derived. One against the live API
cannot, and every report says which it was — a clearance nobody can reproduce
is a claim, not a finding.

## It never runs your dependencies

Source is parsed with `ast`, never imported. `setup.py` is read, never
executed. Archives are unpacked, never installed. A tool that executed what it
analysed would be a worse supply-chain risk than the one it was looking for.

## What it covers

Advisory matching works for every ecosystem OSV publishes. **Reachability is
Python only** — it is a real static analysis, not a heuristic, and one done
properly for one language is worth more than four done badly. Lockfiles read:
`uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `package-lock.json`,
`pnpm-lock.yaml`, `requirements.txt` (pinned).

`vexpath version` prints exactly what the build you have can do, because a
cleared finding means nothing unless you know whether reachability ran.

## In CI

```yaml
- uses: Unknown122-coder/vexpath@v1
  with:
    policy: balanced
```

The Action caches call graphs, writes SARIF for code scanning, and can comment
on the pull request. A cold scan takes minutes; a warm one takes seconds.

## Standards

purl, OSV, CycloneDX 1.4–1.6, SPDX 2.2–2.3, OpenVEX 0.2.0, in-toto Statement
v1, DSSE, Sigstore, SARIF 2.1.0, CVSS 3.x, PEP 440, semver, CEL.

Apache 2.0.
