# ADR-0005 · CEL for policy expressions

## Context
Policies must be expressive enough for conditions over findings (severity, reachability status, age, KEV, scope) and safe to evaluate on untrusted input (no loops, bounded cost). Options: OPA/Rego (powerful, but a Go binary or WASM runtime and a learning curve), a YAML rules DSL (limited, invented), CEL (small, well-specified, used by Kubernetes admission and Google IAM, Python implementation available).

## Decision
Use CEL via `cel-python`. Expose a documented evaluation context (see `04-api-and-cli.md`). Ship presets. The CLI validates policies and reports type errors with positions.

## Consequences
- Non-Turing-complete: no user-defined functions; complex policies combine multiple expressions.
- `cel-python` performance is adequate for hundreds of findings; if it becomes a bottleneck, `cel-rust` bindings are a drop-in.
- Policies live in the repo (`.vexpath.yml`) by default so they are reviewed like code; the dashboard editor writes the same text.
