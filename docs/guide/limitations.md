# Limitations

What this does not do, and what it does badly. A security tool that is vague
about its edges is asking to be trusted where it should not be.

## Reachability is Python only

Advisory matching works for **every ecosystem OSV publishes**. Reachability —
the thing that makes the report short — is Python.

| Ecosystem | Lockfiles read | SBOM in/out | Advisory matching | Reachability |
|---|---|---|---|---|
| PyPI | `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, pinned `requirements.txt` | yes | yes | **yes** |
| npm | `package-lock.json`, `pnpm-lock.yaml` | yes | yes | no |
| Go, Maven, crates.io, RubyGems, NuGet, Packagist, … | via SBOM | yes | yes | no |

For a component in an ecosystem without reachability, the verdict is
`under_investigation` and the report says the ecosystem is unsupported rather
than letting "under investigation" read as "checked". `vexpath version` prints
the list, so a consumer of a report can tell what that build could have known.

This is a deliberate choice, not a backlog item: one language analysed
properly is worth more than four analysed badly, and a reachability engine
that is wrong clears findings it should not. Go is the next one, and the plan
is to import `govulncheck` output rather than write a second analyser.

## A project with no lockfile cannot be scanned

Half of the repositories in our own benchmark could not be scanned at all:
`mkdocs`, `pipx` and `sqlite-utils` commit no lockfile, and `bandit`'s
`requirements.txt` is unpinned.

The refusal is correct — a scan of versions you might have is a report about a
project that might exist — but a tool half of repositories cannot use has a
problem of its own. Reading a dependency specification without a lockfile, and
saying plainly how much less certain the result is, is scheduled work.

Workaround today: generate a lockfile, or pass an SBOM produced by something
else (`--sbom`).

## Symbol coverage is the real limit

A finding can only be cleared if the advisory's fix has been diffed into
functions. Measured on the published corpus, 2026-11-27:

| | |
|---|---|
| PyPI advisories in the corpus | 19,757 |
| — malicious-package records, which have no fix | 12,094 |
| — analysable: they name a fix to diff | 7,663 |
| — analysable, with at least one symbol | 3,053 (39.8 %) |
| **— analysable, with a high- or medium-confidence symbol** | **2,535 (33.1 %)** |
| Symbols extracted | 27,869 across 802 packages |
| Analysable advisories still waiting | 4,610 |

The design target is 60–75 % on the last of those, so this is roughly half way.
Extraction is a resumable crawl over upstream repositories, and a scheduled
job works through the backlog daily while carrying forward everything already
extracted.

**Check the denominator before believing any of these.** Over *all* PyPI
records the same corpus reads 15.5 %, which makes a working system look
broken: two records in three are `MAL-` malicious-package advisories that have
no fix commit and for which reachability is the wrong question entirely —
installing the package is the compromise. That mistake has been made three
times here, once reporting fix-commit recoverability as 32.9 % when it was
88.7 %.

Where the symbols come from, since provenance decides how much a verdict is
worth:

- **24,600** from an advisory's fix commit, diffed directly.
- **3,265** from a tag-to-tag diff, for the two advisories in five that name
  only a release. A tag's commit *is* the release, so diffing it against its
  parent would describe the wrong change; these diff the previous release
  against the fixed one instead, and are recorded at low confidence because a
  release contains more than its fix.
- **4** curated by hand.

So a finding you expected to be cleared may simply have no symbols yet. The
report says `symbols_unknown`, with the reason `no_fix_commit`, rather than
guessing — and the package pages show exactly which advisories have symbols
and which do not.

## What reachability cannot see

- **Dynamic dispatch, `getattr`, plugin registries, templates, serialised
  callables, C extensions.** Unresolved calls are counted and published; a
  high unresolved ratio means the graph could not see much, and a clearance
  from such a graph deserves less weight.
- **Exploitation without your code calling anything** — a parser a framework
  invokes on untrusted input, for instance.
- **Malicious packages.** Reachability is never applied to a `MAL-` advisory:
  the payload runs at install time, so "your code does not call it" is not an
  answer. Those findings are never cleared.
- **Anything reachable only from an entry point you did not declare.** A
  finding unreachable from your web handlers may be reachable from a
  management command.

See [how reachability works](how-reachability-works.md) for the verdicts and
what each one claims.

## Performance

A cold scan parses every dependency's source: **819s for Flask, 576s for
Jinja, 417s for Click** in our benchmark. Warm, from the graph cache: **12s,
10s, 11s**. The cache is keyed per package version, so it survives a lockfile
change for every package that did not move.

If CI is slow, the cache is almost certainly not being restored.

## Attestations

`vexpath attest sign` and `vexpath attest verify` work with a static key, and
keyless signing works where there is an ambient OIDC credential. **Two things
are not implemented:** Rekor inclusion proofs, and keyless *verification* —
checking a certificate and a transparency-log entry against an identity, which
is what `cosign verify-attestation` does.

They are absent rather than half-written on purpose: writing verification
without being able to run it against the real transparency log would be
shipping something nobody has seen work. Verify our releases with
`slsa-verifier` and `gh attestation verify` in the meantime — see
[verifying attestations](verifying-attestations.md).

## The hosted platform

- **An uploaded scan is self-reported.** The platform does not re-run the
  analysis; it stores what a client asserted. The report page says so. It
  becomes more than an assertion when an attestation is verified against a
  transparency log, which is the gap above.
- **Suppressions do not affect your CI gate.** `vexpath scan --policy`
  evaluates locally with no knowledge of the platform, because a build must
  not depend on a dashboard being reachable. A platform suppression is a
  decision about what a team is working on; a local gate is configured in
  `.vexpath.yml`.
- **Rate-limit counters are per process.** One instance only until they move
  to Postgres; two instances each allow the configured rate.
- **Reachability is not re-evaluated when new advisories land.** A verdict is
  as of the scan. Recomputing against stored graphs when the corpus moves is
  designed and not built.

## Things it will not do

- **Execute your dependencies.** Source is parsed, `setup.py` is read and
  never run, archives are unpacked and never installed. A tool that executed
  what it analysed would be a worse supply-chain risk than the one it was
  looking for.
- **Clear a finding without evidence.** The invariant is enforced in three
  places — the finding model, the results model, and every renderer — and the
  renderer test deliberately reaches past the first two, because an untested
  last line of defence is not one.
- **Emit `false_positive` in CycloneDX VEX.** A finding that does not apply
  because the code cannot run is not a mistake in the advisory.

## Reporting a wrong verdict

`vexpath reach . --advisory <id>` prints everything the verdict rests on.
Paste that into an issue. A wrongly *cleared* finding is the most serious bug
this project can have, and it is the one we most want to hear about.
