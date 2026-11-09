# sscp-worker

Background jobs. The API never does heavy work inside a request; it enqueues.

## Job types

| Job | Trigger | Milestone |
|---|---|---|
| `advisory.seed_snapshot` | `make seed-advisories`, and CI | M0 |
| `advisory.sync` | Scheduled, every six hours | M1 |
| `advisory.patchdiff` | After a sync, for advisories with a fix reference | M2 |
| `callgraph.build` | On demand, cached per package version | M2 |
| `scan.hosted` | API request | M4 |
| `scan.ingest` | CLI upload | M4 |

## Queue

The queue is Postgres, not a broker (ADR-0003). At the volumes this platform will see for a long time, a second piece of infrastructure to run, secure and pay for buys nothing. `procrastinate` is introduced in M1 with the first scheduled job; until then the only job is run directly as a command, because a worker loop with nothing to consume would be theatre.

## Running jobs now

```bash
make seed-advisories            # load the frozen advisory snapshot
python -m sscp_worker.main --help
```

Seeding is idempotent: running it twice leaves the database in the same state, which matters because every job in the table above will be retried at some point.
