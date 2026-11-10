# vexpath GitHub Action

Scans your dependencies, and fails the build **only when the vulnerable code
can actually run** — with the call path that proves it.

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"

# Install your project, so reachability has something to analyse.
- run: pip install -e .

- uses: Unknown122-coder/vexpath@v1
  with:
    policy: balanced
```

That is the whole thing for most projects. The step fails when a critical or
high finding's vulnerable code is provably reachable, or when anything in your
tree is known to be exploited in the wild. Everything else is reported and
does not stop you shipping.

## Why your project has to be installed

Reachability means "is there a call path from your code into the function the
advisory's fix changed". Answering it requires reading the dependency's own
source, which means the dependencies have to be on disk. Three ways to get
there, best first:

1. **Install your project** (`pip install -e .`, `uv sync`, `poetry install`)
   before the step. Then everything is importable and the analysis is exact.
2. **Point at a virtual environment** with `environment: .venv`.
3. **Let it download** with `download-missing: true`. It fetches each
   dependency's source from the package index — no installation, nothing
   executed, but it reaches the network and it is slower.

With none of those, the scan still works and still matches advisories, but
nothing can be *cleared*: an absence of paths through code you never read
proves nothing, so those findings come back as `package_not_analysed` rather
than as "safe". The report says so rather than implying a clean bill of
health.

## Make it fast

A cold scan of a real project downloads and parses every dependency: minutes.
A warm one reads cached call graphs: seconds. On the three projects in our own
benchmark, 819s → 12s, 576s → 10s, 417s → 11s. Cache it:

```yaml
- uses: Unknown122-coder/vexpath@v1
  id: vexpath
  with:
    policy: balanced

- uses: actions/cache@v4
  if: always()
  with:
    path: ${{ steps.vexpath.outputs.cache-dir }}
    key: vexpath-graphs-${{ runner.os }}-${{ hashFiles('**/uv.lock', '**/poetry.lock', '**/requirements*.txt') }}
    restore-keys: vexpath-graphs-${{ runner.os }}-
```

Keyed on the lockfile, because the graphs are per package version: a lockfile
that has not changed has the same graphs.

## Code-scanning alerts

The action writes SARIF and tells you where. Uploading it is two lines, and
they are yours rather than ours on purpose — a supply-chain security tool that
silently pulled another action into your build would be an odd thing to trust:

```yaml
permissions:
  security-events: write

steps:
  - uses: Unknown122-coder/vexpath@v1
    id: vexpath
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: ${{ steps.vexpath.outputs.sarif }}
```

`if: always()` matters: without it a failing gate means no alerts, and the run
that failed is the one you want the alerts from.

## Pull request comments

```yaml
permissions:
  pull-requests: write

- uses: Unknown122-coder/vexpath@v1
  with:
    comment: auto    # only when something needs attention
```

Uses the `gh` CLI that is already on every GitHub-hosted runner, with the
job's own token. No third-party action, no credential of its own.

## If you already have vexpath installed

```yaml
- run: uv sync          # or: pip install -e '.[dev]'
- run: echo "$PWD/.venv/bin" >> "$GITHUB_PATH"
- uses: Unknown122-coder/vexpath@v1
  with:
    vexpath-version: none
```

Use the one your project pins rather than a second copy. The step fails with a
clear message if nothing is on PATH, because "command not found" three steps
later explains nothing.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Directory to scan. |
| `policy` | `balanced` | The gate: a preset (`strict`, `balanced`, `kev-only`, `nothing-outstanding`, `report-only`), a file path, or a CEL expression. Empty means report only. |
| `reachability` | `true` | Run the analysis. Off is fast, and nothing can be cleared. |
| `environment` | — | Virtual environment holding the dependencies. |
| `download-missing` | `false` | Fetch dependency source from the index. Reaches the network. |
| `entry-points` | — | `module.path:function`, comma-separated. Overrides inference, and nothing beats being told how the application starts. |
| `sbom` | — | Analyse this SBOM instead of generating one. |
| `lockfile` | — | Use this lockfile instead of searching. |
| `snapshot` | — | Read advisories from a local snapshot: reproducible and offline. |
| `ignore-dev` | `false` | Exclude development dependencies. |
| `summary` | `auto` | Write the report to the job summary. `auto` only when something needs attention. |
| `comment` | `never` | Comment on the PR. `auto`, `always`, `never`. |
| `upload` | `false` | Send the result to the platform. Needs `VEXPATH_API_KEY` and `project`. |
| `project` | — | Project slug for the upload. |
| `sign` | `false` | Sign the result with the workflow's own identity. Needs `id-token: write`. |
| `vexpath-version` | pinned | A PyPI specifier; `none` to use a vexpath already on PATH; or `path:<dir>[,<dir>...]` to install from a checkout. |
| `working-directory` | `.` | Where the output files are written. |

## Outputs

| Output | What it is |
|---|---|
| `results` | The JSON result document. Everything else is rendered from it. |
| `sarif` | The SARIF file, for code scanning. |
| `markdown` | The Markdown report. |
| `needs_attention` | How many findings a person should look at. |
| `cleared` | How many the analysis cleared as unreachable. |
| `reachable` | How many have vulnerable code that can run. |
| `reachability_analysed` | Whether the search ran at all. A `cleared` of zero means something different when this is `false`. |
| `policy_passed` | `true`, `false`, or empty when there was no gate. |
| `cache-dir` | The call-graph cache directory, for `actions/cache`. |

## The order the steps run in, and why

Scan → render → summary → comment → sign → upload → **gate last**.

The gate is last so that a build which fails it still has its report, its
SARIF, its comment and its uploaded record. The run that fails a gate is the
one somebody most needs to read, and a pipeline that exits before producing
the evidence makes that impossible.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing the policy objects to. |
| 1 | The policy failed. Your dependencies need attention. |
| 2 | The analysis failed — a broken lockfile, an unreachable index. |
| 3 | Configuration is wrong: a policy that does not compile, a missing API key. |

1 and 2 are kept apart deliberately: a build failing because the code is
vulnerable must never look like a build failing because the tool broke.

## Permissions

Nothing by default beyond `contents: read`. Add only what you use:

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # comment
  id-token: write          # sign
```

## What this is not

It is not a container action. Reachability needs your dependencies readable on
disk, and a container has its own filesystem where your virtual environment
does not exist — every finding would come back "package not analysed" and
nothing could ever be cleared. It runs on the runner, in your checkout, with
the Python you set up.

It does not upload SARIF, comment, or manage a cache by itself. Each is two
lines above, and they are composable, visible and yours.
