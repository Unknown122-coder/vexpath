# ADR-0001 · Python 3.12 for the analysis core; FastAPI for the API

## Context
The core must parse Python source precisely (stdlib `ast` gives exact, version-aligned parsing with line/column spans), evaluate PEP 440 ranges (`packaging`), and integrate with `sigstore-python`, `cyclonedx-python-lib`, `spdx-tools` and `packageurl-python`, all mature in Python. The team's existing projects are Python-first. The API is thin and I/O-bound.

## Decision
- `packages/core` is Python 3.12+, typed (`mypy --strict`), Pydantic v2 models, zero framework imports.
- `apps/api` is FastAPI with async SQLAlchemy Core, serving both the JSON API and the HTML UI (ADR-0011); `apps/worker` shares the same codebase.
- The CLI uses Typer.

## Consequences
- The whole system is one language, which keeps the analysis core, the CLI, the API, the UI and the tests maintainable by one person.
- CPU-heavy call-graph builds run in worker processes, not in the API process.
- A Go or Rust rewrite of hot paths (graph search) is possible later behind the same interfaces if profiling demands it; not planned.
