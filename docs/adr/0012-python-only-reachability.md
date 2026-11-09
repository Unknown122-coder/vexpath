# ADR-0012 · Python is the only reachability ecosystem in v1

## Context

The original plan had Python reachability first and JavaScript/TypeScript second, using tree-sitter grammars. Two facts changed the calculation:

1. The project is maintained by a developer who does not write JavaScript. A JavaScript call-graph builder demands deep knowledge of CommonJS versus ESM resolution, `package.json` `exports` maps, bundler conventions, TypeScript declaration files and prototype-based dispatch. Building that without fluency in the language produces a builder whose false verdicts cannot be recognised, let alone fixed. For a tool whose entire value is verdict trustworthiness, that is disqualifying.
2. JavaScript reachability is genuinely harder than Python's. Without type information, method dispatch on an untyped receiver is nearly unresolvable, so results would sit mostly at `low` confidence anyway.

Depth in one ecosystem is worth more than shallow coverage of two. Python is also the ecosystem where the author can build the benchmark set, review verdicts manually and defend the design.

## Decision

- **Reachability analysis supports Python only in v1.** The call-graph builder, entry-point detection, symbol extraction and benchmark are all Python.
- **Vulnerability matching and SBOM handling stay multi-ecosystem.** Lockfile parsing for npm (`package-lock.json`, `pnpm-lock.yaml`) is ordinary JSON and YAML parsing in Python and needs no JavaScript knowledge, so npm projects still get SBOM generation, advisory matching, VEX, attestation and policy. They simply get `symbols_unknown` for every finding, which maps to OpenVEX `under_investigation`.
- **The UI and API state this plainly.** A per-ecosystem capability matrix is shown next to results so no user mistakes "under investigation" for "we checked and it is fine".
- The two-level graph design (per-package graphs, link at scan time) is kept language-neutral so another ecosystem can be added later without reworking the linking and search layers.

## Consequences

- The reachability benchmark and the zero-false-`not_affected` guarantee cover Python only, and the documentation says so.
- Post-v1 ecosystem expansion is ordered by what can be done without authoring another language's analyser: importing `govulncheck` results for Go first, since Go's official tool already computes reachability and we only need to ingest its output.
- If JavaScript reachability becomes necessary, it is a scoped project for a contributor who knows the language, not a solo stretch goal.
