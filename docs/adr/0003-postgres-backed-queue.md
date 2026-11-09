# ADR-0003 · Postgres-backed job queue instead of a broker

## Context
Jobs: advisory sync (scheduled), patch diffing (bursty after syncs), call-graph builds (on demand, cacheable), hosted scans and result ingest (user-triggered). Throughput is low (hundreds of jobs per hour at most for a long time). Adding Redis or RabbitMQ means another service to run, secure and pay for.

## Decision
Use `procrastinate`, a Postgres-based task queue for Python with `LISTEN/NOTIFY`, retries, scheduling and periodic tasks. Jobs are idempotent and keyed (`callgraph.build` is unique per package version; `scan.ingest` per scan id).

## Consequences
- One database to back up, monitor and secure.
- Transactional enqueue: a scan row and its job are committed together.
- If queue load ever contends with API traffic, move the queue to its own Postgres instance before considering a broker.
