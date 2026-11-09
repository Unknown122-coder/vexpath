# vexpath

The command-line tool. This is the primary way the platform is used: analysis runs where the code already is, and only results travel (ADR-0010).

```bash
uv tool install vexpath      # or: pipx install vexpath
vexpath --help
```

## Exit codes

The exit code is the contract with CI, so it is fixed:

| Code | Meaning |
|---|---|
| 0 | Analysis completed and the policy passed |
| 1 | Analysis completed and the policy failed |
| 2 | Analysis could not complete (parse failure, missing lockfile, upstream outage) |
| 3 | Configuration error (bad policy expression, unreadable `.vexpath.yml`, invalid flags) |

A policy failure and a broken scan are deliberately different codes. A build that fails because the scanner crashed must not look like a build that fails because the code is vulnerable.

## Commands available now

M0 ships the application skeleton and `vexpath version`. The full command set is specified in `docs/04-api-and-cli.md` and arrives with the milestone that implements each capability:

| Command | Milestone |
|---|---|
| `vexpath sbom generate` / `validate` | M1 |
| `vexpath advisory sync` / `show` | M1 |
| `vexpath scan --no-reach` | M1 |
| `vexpath scan` with reachability, `vexpath reach` | M2 |
| `vexpath vex export`, `vexpath attest sign` / `verify`, `vexpath policy test` | M3 |
| `vexpath login`, `vexpath whoami`, uploads | M4 |
