# sscp

The command-line tool. This is the primary way the platform is used: analysis runs where the code already is, and only results travel (ADR-0010).

```bash
uv tool install sscp      # or: pipx install sscp
sscp --help
```

## Exit codes

The exit code is the contract with CI, so it is fixed:

| Code | Meaning |
|---|---|
| 0 | Analysis completed and the policy passed |
| 1 | Analysis completed and the policy failed |
| 2 | Analysis could not complete (parse failure, missing lockfile, upstream outage) |
| 3 | Configuration error (bad policy expression, unreadable `.sscp.yml`, invalid flags) |

A policy failure and a broken scan are deliberately different codes. A build that fails because the scanner crashed must not look like a build that fails because the code is vulnerable.

## Commands available now

M0 ships the application skeleton and `sscp version`. The full command set is specified in `docs/04-api-and-cli.md` and arrives with the milestone that implements each capability:

| Command | Milestone |
|---|---|
| `sscp sbom generate` / `validate` | M1 |
| `sscp advisory sync` / `show` | M1 |
| `sscp scan --no-reach` | M1 |
| `sscp scan` with reachability, `sscp reach` | M2 |
| `sscp vex export`, `sscp attest sign` / `verify`, `sscp policy test` | M3 |
| `sscp login`, `sscp whoami`, uploads | M4 |
