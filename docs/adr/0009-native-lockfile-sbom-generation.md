# ADR-0009 · Native lockfile-based SBOM generation with Syft as fallback

## Context
Syft is the de facto open-source SBOM generator but it is a Go binary, which complicates a pure-Python CLI install, and its Python support depends on installed environments or lockfile heuristics we would have to post-process anyway. Reachability needs *exact* resolved versions and the dependency graph (who pulls in what), which lockfiles provide directly.

## Decision
- Native parsers for Python (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`, pinned `requirements*.txt` with hashes) and for npm (`package-lock.json` v2/v3, `pnpm-lock.yaml`) producing components *and* edges, with `scope` from dependency groups. The npm parsers read JSON and YAML, so they need no JavaScript knowledge to maintain; `yarn.lock`'s bespoke format is left to Syft.
- Unpinned `requirements.txt` is rejected for scanning with a clear message (generate a lockfile first); it is accepted for `sbom generate` with a warning and no reachability.
- Syft is wrapped (`--syft`) when present for other ecosystems and container images; its output is ingested through the normal CycloneDX path.

## Consequences
- Our own parsers to maintain as lockfile formats evolve; covered by fixtures per format version.
- Users without lockfiles are pushed toward best practice rather than silently served imprecise results.
