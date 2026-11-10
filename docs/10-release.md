# 10 · Releasing

Six packages, one version, one tag. They import each other's internals and
pin each other at an exact version, so they are released together or not at
all.

| Package | What it is | Published |
|---|---|---|
| `vexpath-core` | The analysis. No framework, no database, no web server. | PyPI |
| `vexpath-platform` | Settings, logging, keys, sessions, rate limits. | PyPI |
| `vexpath-db` | Tables and migrations. | PyPI |
| `vexpath` | The command-line tool. **This is what people install.** | PyPI |
| `vexpath-api` | The hosted platform and its HTML UI. | PyPI + GHCR image |
| `vexpath-worker` | The advisory pipeline. | PyPI + GHCR image |

## Cutting a release

```sh
# 1. One version, everywhere. A test refuses a mismatch, and so does the
#    release workflow before it builds anything.
#    packages/*/pyproject.toml, apps/*/pyproject.toml, and the pinned
#    `vexpath-core==X.Y.Z` in each dependent.

# 2. The pinned version in the Action, which must be a release that exists.
#    apps/action/action.yml -> pinned="X.Y.Z"   (a test asserts this matches)

# 3. Prove it builds, installs on its own, and runs.
make dist

# 4. The gate.
make check && make test-all && make e2e

# 5. Tag it. The workflow refuses a tag that disagrees with the metadata.
git tag -s vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

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

1. **A PyPI project with Trusted Publishing configured** — repository,
   workflow filename `release.yml`, environment `pypi`. There is no token to
   create, which is the point.
2. **The `pypi` environment** in the repository settings, ideally with a
   required reviewer.
3. **The Action on the Marketplace**, which needs the repository public and a
   release published. The Action itself is finished and this repository runs
   it on itself on every push.

## Version numbers

`0.0.x` while the schema and the command surface can still move. The things
that constrain a bump:

- **`vexpath.results/N`**, the results schema identifier, which the platform
  validates uploads against. A breaking change to it is a new `N`, not a new
  version — old documents keep being readable.
- **Exit codes**, which are a contract with CI and do not change.
- **The Action's inputs**, which are a contract with other people's
  workflows: an input may be added, never removed or quietly redefined.
