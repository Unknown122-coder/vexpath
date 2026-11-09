# vexpath-db

The database schema, in one place, so the API and the workers cannot disagree about it.

This package exists for a boundary reason: `vexpath-core` must never import SQLAlchemy, because the analysis core has to run on a developer's laptop with no database at all. But the API and the worker both need the same tables, and neither should import the other. So the tables live here and both depend on this package.

## Contents

| Module | Purpose |
|---|---|
| `tables` | SQLAlchemy Core table definitions and the shared `MetaData` |
| `engine` | Engine and session construction for sync and async use, from one URL |
| `migrations` | Alembic environment and revision history |

## Driver choice

One driver, `psycopg` version 3, for both synchronous and asynchronous access. SQLAlchemy reaches it as `postgresql+psycopg://`, Alembic uses the same URL synchronously, and `procrastinate` uses psycopg too. Running a single driver means one set of connection semantics and type adapters to understand.

## Migrations

```bash
make migrate                      # upgrade the local database to head
make migration m="add findings"    # autogenerate a revision from the tables module
```

Autogenerate compares the live database against `tables.metadata`, so a table is created by editing `tables.py` and then generating a revision, never the other way round.

## Scope at this milestone

M0 defines only the **global** tables: advisories, their affected ranges, vulnerable symbols, advisory snapshots, and the call-graph cache index. These are the read-only, non-tenant tables that the advisory pipeline fills.

Tenant tables (organisations, projects, scans, findings, suppressions, audit log) arrive in M4 together with row-level security, because nothing writes them before then. The full target schema is specified in `docs/02-data-model.md`.
