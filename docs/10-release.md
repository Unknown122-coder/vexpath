# 10 · Releasing

Six packages, one version, one tag — but only **two go to PyPI**. They import
each other's internals and pin each other at an exact version, so they are
built and versioned together whether or not they are published.

| Package | What it is | Published |
|---|---|---|
| `vexpath-core` | The analysis. No framework, no database, no web server. | **PyPI** |
| `vexpath` | The command-line tool. **This is what people install.** | **PyPI** |
| `vexpath-platform` | Settings, logging, keys, sessions, rate limits. | GHCR image only |
| `vexpath-db` | Tables and migrations. | GHCR image only |
| `vexpath-api` | The hosted platform and its HTML UI. | GHCR image only |
| `vexpath-worker` | The advisory pipeline. | GHCR image only |

Only two because only two are needed: `vexpath` is the product and
`vexpath-core` is what it depends on. The other four matter to somebody
self-hosting from pip rather than from the container image, and there is a
container image. Four fewer names to keep in step, and four fewer claims on
the index.

**Each published package has its own publish job and its own GitHub
environment** (`pypi-core`, `pypi`), and that is forced rather than chosen: a
PyPI *pending* publisher is keyed on the whole configuration — owner,
repository, workflow filename **and environment** — so two packages claiming
unclaimed names from one identical configuration is refused. Separate
environments make the configurations differ, and incidentally give each
package its own approval gate. The core publishes first, because `vexpath`
pins it at an exact version and an installer that found one without the other
would resolve nothing.

## Cutting a release

```sh
# 1. One version, everywhere -- ten places across eight files, so it is a
#    tool rather than an edit. It refuses a version that is not one, and
#    reads everything back to check nothing disagrees.
uv run python tools/bump_version.py X.Y.Z

# 2. Prove it builds, installs on its own, and runs.
make dist

# 3. The gate.
make check && make test-all && make e2e

# 4. Optional but recommended for a first release: a dry run in CI, which
#    does the version check, the gate and the install proof and publishes
#    nothing.
gh workflow run release.yml -f dry-run=true

# 5. Tag it. The workflow refuses a tag that disagrees with the metadata.
#    -s signs the tag and needs a GPG or SSH signing key configured; -a is an
#    annotated tag without one. Either is fine: what a consumer actually
#    verifies is the SLSA provenance and PyPI's attestation, both produced by
#    the workflow, not the tag.
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

Pushing the tag is the irreversible step. PyPI does not allow a version to be
replaced or a name to be released, so a tag pushed in error is fixed by a new
version rather than undone.

## What the workflow does, and the order it does it in

1. **Refuses a tag that disagrees with the version.** A release nobody can
   find by version is worse than no release.
2. **Runs the gate.** Lint, format, types, unit tests. The integration and
   acceptance suites already ran on the push; a release must not be the first
   time anybody looks.
3. **Builds, installs into an empty environment, and runs the command.** This
   is not a formality — see below.
4. **Produces SLSA provenance** with the official generator, run as its own
   reusable workflow. A statement about what built an artefact is worth less
   when the thing making the statement is the thing being described.
5. **Publishes to PyPI** with Trusted Publishing, from a protected
   environment. No API token exists anywhere in this repository.
6. **Builds and pushes the container image** to GHCR with its own provenance
   attestation.

Publishing is the one irreversible step, which is why it is last and why the
`pypi` environment can require a review.

## Why step 3 exists

Everything in the test suite runs inside the workspace, where every package is
already installed. A module imported without being declared as a dependency
therefore passes every test and fails on install.

That happened. The command-line tool imported `vexpath_platform` for three
constants about the shape of an API key; a published `vexpath` would have been
broken for everybody with
`ModuleNotFoundError: No module named 'vexpath_platform'`. It was found by
building a wheel and installing it into an empty environment, which is what
`make dist` now does, and the format moved to `vexpath_core.keyformat` so the
command line never depends on the server package.

Two tests guard the class of bug permanently: every workspace import must be
declared, and the layers must point one way (core at the bottom, nothing
reaching back up). Neither replaces the install.

## A version is never republished

Rebuilding the same version with different contents poisons every cache
between you and the user. The first run of `verify_dist.py` "passed" against a
stale `vexpath-core` wheel and reported a module missing that was in the new
build all along — a cache hit on an unchanged version number.

PyPI refuses a re-upload, and the workflow sets `skip-existing: false` so a
version already published fails the release rather than silently doing
nothing. **A mistake in a release is fixed by a new version, never by
replacing one.**

## Verifying a release

What somebody else can check, and should be able to:

```sh
# The provenance of the distributions.
slsa-verifier verify-artifact vexpath-X.Y.Z-py3-none-any.whl \
  --provenance-path vexpath-X.Y.Z-py3-none-any.whl.intoto.jsonl \
  --source-uri github.com/Unknown122-coder/vexpath \
  --source-tag vX.Y.Z

# PyPI's own attestation, shown on the project page under each file.

# The image.
gh attestation verify oci://ghcr.io/unknown122-coder/vexpath:X.Y.Z \
  --repo Unknown122-coder/vexpath
```

This is the same claim the tool makes about other people's artefacts, so it
has to hold for its own. A supply-chain tool whose releases cannot be verified
is making an argument against itself.

## Before the first release

Three things need accounts and are not done yet:

1. **Two PyPI pending publishers**, both with owner `Unknown122-coder`,
   repository `vexpath` and workflow `release.yml`, differing only in the
   project name and environment: `vexpath` with `pypi`, and `vexpath-core`
   with `pypi-core`. There is no token to create, which is the point.
2. **The `pypi` and `pypi-core` environments** in the repository settings,
   ideally each with a required reviewer. Note that environment protection
   rules need GitHub Pro or Team on a private repository; without them the
   environments still work, and the gate is simply that a tag has to be
   pushed deliberately.
3. **The Action on the Marketplace** — listed since 2026-11-13. Two things
   the publish form insists on and says nothing about until it refuses:
   `action.yml` has to be in the **root** of the repository, and the
   `description` has to be under 125 characters. Both are asserted by
   `apps/action/tests/test_action.py` now, because each refusal arrives
   without naming the field at fault.

## Version numbers

`0.x` while the command surface can still move. `0.1.0` is the first release
anybody is asked to install; `0.0.1` was the scaffold. `0.1.2` is the first
cut from a public repository, and so the first whose image carries a GitHub
artifact attestation: the API refuses to record one for a private
user-owned repository, which is why that job failed on the two before it. The things that
constrain a bump:

- **`vexpath.results/N`**, the results schema identifier, which the platform
  validates uploads against. A breaking change to it is a new `N`, not a new
  version — old documents keep being readable.
- **Exit codes**, which are a contract with CI and do not change.
- **The Action's inputs**, which are a contract with other people's
  workflows: an input may be added, never removed or quietly redefined.
