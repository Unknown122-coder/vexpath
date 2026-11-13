# Quickstart

Five minutes, and then the one thing that makes the difference.

## Install

```bash
uv tool install vexpath      # or: pipx install vexpath
vexpath version
```

`vexpath version` prints what your build can actually do. Worth reading once:
a cleared finding means nothing unless you know whether reachability ran.

## Scan

```bash
cd your-project
pip install -e .        # or: uv sync, or: poetry install
vexpath scan .
```

```
SEVERITY  VERDICT       ADVISORY         COMPONENT              REACHABILITY
--------------------------------------------------------------------------------
HIGH      affected      CVE-2026-1234    jinja2 3.1.0           reachable_confirmed
MEDIUM    not_affected  CVE-2026-5678    urllib3 2.2.1          unreachable

38 findings | 10 reachable | 28 not affected | 0 under investigation
```

## The thing that makes the difference

**Install your project first.** Reachability means "is there a call path from
your code into the function this advisory's fix changed", and answering it
requires reading the dependency's own source. With nothing installed, vexpath
still matches advisories but can clear nothing — an absence of paths through
code it never read proves nothing, and it says so rather than implying a clean
bill of health.

Three ways, best first:

```bash
pip install -e .                      # 1. the real thing
vexpath scan . --environment .venv    # 2. point at an environment
vexpath scan . --download-missing     # 3. fetch source from the index
```

The third reaches the network and is slower. Nothing is ever executed: source
is parsed, `setup.py` is read and never run, archives are unpacked and never
installed.

## Tell it how your application starts

Nothing beats being told. Inference is good; a declaration is better.

```bash
vexpath scan . --entry-point 'myapp.main:main,myapp.web:app'
```

Or in `.vexpath.yml`:

```yaml
entry_points:
  - myapp.main:main
  - myapp.web:app
```

Without it, vexpath looks for console scripts, `__main__` blocks, framework
routes and tasks, and falls back to every public function of your own modules.
That fallback is deliberately pessimistic: it finds more paths, so it clears
less.

## Disagree with a verdict

```bash
vexpath reach . --advisory CVE-2026-1234
```

It shows the symbols it searched for and where they came from, which of them
exist in the version you have, which entry points reach them and by what path,
and how good the call graph was. If the answer is wrong, this is where you see
why — and if we are wrong, this is what to put in the issue.

## Gate your build

```bash
vexpath scan . --policy balanced
```

Exits **1** when a critical or high finding's vulnerable code is provably
reachable, or when anything in your tree is in CISA's Known Exploited
Vulnerabilities catalogue. See the presets:

```bash
vexpath policy list
vexpath policy explain balanced
```

Try one against a scan you already have, without re-scanning:

```bash
vexpath scan . --format json > results.json
vexpath policy test 'findings.exists(f, f.kev)' --scan results.json
```

Exit codes are the contract with CI: **0** fine, **1** the policy failed,
**2** the analysis failed, **3** the configuration is wrong. 1 and 2 are
separate on purpose — a build failing because the code is vulnerable must
never look like one failing because the tool broke.

## In CI

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install -e .

- uses: Unknown122-coder/vexpath@v1
  id: vexpath
  with:
    policy: balanced

- uses: actions/cache@v4
  if: always()
  with:
    path: ${{ steps.vexpath.outputs.cache-dir }}
    key: vexpath-graphs-${{ runner.os }}-${{ hashFiles('**/uv.lock', '**/requirements*.txt') }}
```

Cache the graphs. A cold scan takes minutes; a warm one takes seconds — on our
own benchmark, 819s to 12s.

Full options: [the Action's README](../../apps/action/README.md).

## Get the corpus first

```bash
vexpath advisory pull
```

**Do this before anything else.** Without it a scan reads advisories live from
OSV, and OSV does not publish which functions a fix changed -- so nearly every
finding comes back `symbols_unknown`: nobody could look. That is an honest
answer and a useless one, and it is what the tool says until it has a corpus.

The corpus is about ten megabytes and holds the vulnerable symbols extracted
by diffing each advisory's fix commit: hours of cloning upstream repositories,
done once and published so nobody repeats it. It lands in a per-user cache and
every command finds it from then on, with no flag and no environment variable.

It is verified on arrival. The content hash is recomputed over the records and
checked against what the snapshot claims, and a corpus that fails is discarded
rather than used -- a substituted one would change verdicts, which is not an
acceptable degraded mode.

## Offline, and reproducible

```bash
vexpath advisory sync --ecosystem PyPI --dir ./advisories   # build your own
vexpath scan . --snapshot ./advisories
```

`advisory pull` already gives you a pinned snapshot; `sync` is for building
one yourself, from a different ecosystem or at a moment you choose.

A scan against a pinned snapshot can be re-derived months later. One against
the live API cannot, and every report says which it was. A clearance nobody
can reproduce is a claim rather than a finding, and the distinction is on the
page.

## Publish the conclusions

```bash
vexpath vex export --format openvex -o vex.json     # or cyclonedx
vexpath attest sign vex.json --type vex             # keyless in CI, --key elsewhere
```

The VEX statement is about **your product**, with the vulnerable dependency as
a subcomponent — which is the part most tools get wrong. The only justification
reachability earns is "vulnerable code not in execute path"; generating any
other raises.

## Where to go next

- [How reachability works](how-reachability-works.md) — what a clearance
  actually rests on.
- [Limitations](limitations.md) — what this does not do, per ecosystem.
- [Verifying attestations](verifying-attestations.md) — checking our claims,
  and ours about yours.
