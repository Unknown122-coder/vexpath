# vexpath-worker

Background jobs. The API never does heavy work inside a request; it enqueues.

## Job types

| Job | Trigger | Milestone |
|---|---|---|
| `advisory.seed_snapshot` | `make seed-advisories`, and CI | M0 |
| `advisory.sync` | Scheduled, four times a day | M1 |
| `advisory.patchdiff` | After a sync, for advisories with a fix reference | M2 |
| `callgraph.build` | On demand, cached per package version | M2 |
| `scan.hosted` | API request | M4 |
| `scan.ingest` | CLI upload | M4 |

## Queue

The queue is Postgres, not a broker (ADR-0003). At the volumes this platform will see for a long time, a second piece of infrastructure to run, secure and pay for buys nothing.

`procrastinate` arrives in M4 with scan ingest, the first user-triggered job. The advisory sync turned out not to need it: that job is scheduled, so a cron trigger invoking the command does the whole thing with nothing to enqueue. A worker loop before anything enqueues work would be infrastructure with no purpose.

## Running jobs now

```bash
make seed-advisories            # load the frozen advisory snapshot
python -m vexpath_worker.main --help
```

Seeding is idempotent: running it twice leaves the database in the same state, which matters because every job in the table above will be retried at some point.
