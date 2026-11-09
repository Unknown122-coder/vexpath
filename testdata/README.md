# Test data

Everything the test suite needs in order to run with no network access and produce the same result every time.

## `advisories/` — the frozen advisory snapshot

A snapshot directory in the format `sscp_core.snapshot` reads:

```
snapshot.json      metadata: id, created_at, content_sha256, ecosystems, counts
advisories.jsonl   one normalised advisory per line, sorted by id
```

Regenerate it with `make regen-snapshot`, which runs `tools/build_test_snapshot.py`. The content hash is computed from the advisories, so editing `advisories.jsonl` by hand will make the integrity check fail. Edit the script instead.

**What is real and what is not.** Advisory identifiers, affected version ranges, fixed versions, severities and references are real, because tests that match versions should match real ones. Identifiers beginning `CVE-2024-FIXTURE-` are invented and exist only to exercise a code path that no convenient real advisory covers.

**Vulnerable symbols are hand-authored.** Every symbol in this snapshot has `source: curated` and no fix commit. They are plausible targets chosen for the fixtures, not the output of diffing a real fix. Extracting symbols from real fix commits is what the patch-diff worker does (M2); claiming it here would put unverified assertions into a file that looks authoritative.

## `repos/` — fixture repositories

Six tiny Python projects, each exercising one reachability case. Every verdict rule in `docs/03-reachability-design.md` section 5 is covered by at least one of them.

| Fixture | What it proves |
|---|---|
| `direct-call` | A plain call into a dependency reaches the vulnerable symbol through the package's own internals |
| `method-chain` | Assignment tracking resolves an instance in a local variable and on `self` |
| `subclass-override` | Class-hierarchy analysis finds the override that actually runs |
| `dynamic-dispatch` | A `getattr` path yields `reachable_possible` with low confidence, never `confirmed` and never `unreachable` |
| `unused-transitive` | A dependency that is present but never imported yields `not_affected` with a justification |
| `module-level` | A module-level vulnerable symbol is reached by the import alone |

Each fixture has an `expected.yaml` naming the verdict, reachability status, confidence and the symbols that must appear. The benchmark harness (M2) reads these, and CI fails on any disagreement. One rule is absolute: a fixture expecting `affected` must never be reported `not_affected`.

`dynamic-dispatch` vendors a synthetic package under `vendor/fixturelib` rather than depending on something real. A fixture that exists to test dynamic dispatch needs a dependency whose shape is fixed forever, and vendoring it keeps the fixture self-contained.

The fixture sources are excluded from linting and type-checking. They are inputs to the analyser, so they must stay exactly as written, including the awkward constructs that are the point.

## `sboms/` — bill of materials documents

| File | Covers |
|---|---|
| `direct-call.cdx-1.6.json` | CycloneDX 1.6 with dependency edges, licences, hashes and a dev-scoped component |
| `direct-call.spdx-2.3.json` | The same inventory as SPDX 2.3, so parsers can be checked for equivalence |
| `mixed-ecosystems.cdx-1.6.json` | PyPI, npm with a scoped package, and Go, to exercise purl normalisation and the unsupported-reachability path |

The two `direct-call` documents describe the same project. A test asserts that both parse to the same component set, which is how format drift gets caught.
