# 09 · Deployment

One container image, three things it can be: the API and HTML UI, the advisory
pipeline on a schedule, and the migration runner. Managed Postgres (Neon) is
the only dependency that has to exist.

This document is the runbook. It is written so that somebody who has never
deployed this can do it, and so that somebody who has can tell whether it is
healthy.

## What has to exist first

**To serve at all**, two things:

| Thing | Why |
|---|---|
| A Fly.io account and `flyctl` | The host. Render works the same way; the `fly.toml` here is the one that is maintained. |
| A Neon Postgres database | Everything structured, including the job queue (ADR-0003). |

**To let anybody sign in**, one more:

| Thing | Why |
|---|---|
| A GitHub OAuth app | Callback URL **must** be `<base-url>/auth/github/callback`. Without it the deployment serves every public page and the sign-in page says it is not configured, which is a usable state to deploy in. |

**Not yet needed**, despite having settings:

| Thing | Why not |
|---|---|
| A Cloudflare R2 bucket | `VEXPATH_S3_*` exists in the configuration and **nothing reads it**: no artefact is written to object storage yet. Create it when something does, not before. |
| A GitHub token | `VEXPATH_GITHUB_TOKEN` is declared and **nothing reads it**, like the S3 settings above. Symbol extraction talks to `git`, not to GitHub's API, so no rate limit applies to it. The setting is here for resolving tag references, which is not built yet. |

Put the Fly app in the **same region as the database**. Every request makes
several round trips to Postgres, so the distance between them is paid
repeatedly on every page. `fly.toml` says `sin` because the Neon project is in
`ap-southeast-1`; if you move one, move both.

Fly app names are globally unique. If `vexpath` is taken, pick another, and
change both `app` in `fly.toml` and `VEXPATH_BASE_URL` to match — the base URL
is what the session cookie and the OAuth callback are built from, so a
mismatch there means sign-in silently never completes.

## Secrets

Set with `fly secrets set`, which stores them encrypted and keeps them out of
this repository and out of every image layer. None of these has a default
outside local development: a missing secret fails at start-up rather than
falling back to something insecure.

```sh
# The two that are actually required.
fly secrets set \
  VEXPATH_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  VEXPATH_DATABASE_URL='postgresql://…neon.tech/neondb?sslmode=require'

# When you want sign-in to work.
fly secrets set VEXPATH_GITHUB_CLIENT_ID=… VEXPATH_GITHUB_CLIENT_SECRET=…

# Optional, any time.
fly secrets set VEXPATH_SENTRY_DSN=…        # the only one that does anything
```

The database URL is pasted from Neon unchanged: the driver is rewritten to
psycopg either way, so the `postgresql://` form a provider gives you works.

**`VEXPATH_SECRET_KEY` is load-bearing in three places and rotating it is not
free.** It signs session cookies (every session ends), signs the OAuth state
parameter (sign-ins in flight fail and have to be restarted — harmless), and
derives the key that encrypts **webhook signing secrets**, which become
unreadable. After a rotation, webhook deliveries are recorded as `refused`
with "re-issue this secret", and every webhook has to be rotated from the
dashboard. Rotate deliberately, not routinely.

`VEXPATH_ENV=production` additionally refuses to start when the secret key is
still the local placeholder, and when `VEXPATH_BASE_URL` is not `https`.

## First deploy

```sh
fly apps create vexpath
# Same region as the app and the database. 3GB is the free allowance and is
# plenty: the volume holds the advisory snapshot and the call-graph cache,
# both rebuildable.
fly volumes create vexpath_data --region sin --size 3
fly secrets set …                      # above
fly deploy -c infra/fly.toml
```

The deploy runs `alembic upgrade head` as a release command **before** any new
machine takes traffic. If it fails the deploy stops, which is intended: code
that expects a column must not serve requests before that column exists.

## After the deploy, check these four things

```sh
curl -fsS https://vexpath.fly.dev/healthz   # the process is alive
curl -fsS https://vexpath.fly.dev/readyz    # it can reach the database
curl -fsSo /dev/null -w '%{http_code}\n' https://vexpath.fly.dev/login   # 200
curl -fsS https://vexpath.fly.dev/package/PyPI/requests | head -5   # a page
fly logs -c infra/fly.toml | head -20      # one JSON line per request
```

`/readyz` answering 503 while `/healthz` answers 200 means the process is fine
and the database is not — that pairing is deliberate, so a database outage
stops traffic reaching a machine without restarting it in a loop.

Then sign in once. If the GitHub callback URL is wrong, the sign-in page says
so rather than failing silently; if the OAuth credentials are absent, it says
sign-in is not configured.

## Loading the corpus for the first time

A fresh deployment has an empty database, which is a working deployment with
nothing to say. The corpus is one command, and these are measurements of the
real thing rather than estimates (2026-11-11, PyPI only, loaded from a Fly
machine in `sin` into Neon in `ap-southeast-1`):

| | |
|---|---|
| Advisories | 19,575 |
| Affected packages | 21,176 |
| Download | 19 seconds |
| Load | 19 seconds |
| Snapshot on disk | 48 MB of JSONL |
| In the database | 60 MB |
| EPSS coverage | 99.2% |
| In CISA KEV | 22 |

```sh
fly ssh console -c infra/fly.toml -C   "python -m vexpath_worker.main sync-advisories --ecosystem PyPI /data/advisories"
```

Run it on the app machine, which already has the database URL and the volume
mounted; it does not need its own machine.

**Watch the storage, but it is roomier than it looks.** 48MB of JSONL became
60MB of rows and indexes, against Neon's free 0.5GB: one ecosystem costs
about an eighth of the allowance. npm is roughly four times the size of PyPI,
and extracted symbols add rows per advisory rather than per package, so there
is room for both and not for carelessness. Neon stops accepting writes rather
than billing, so check before adding an ecosystem rather than after:

```sh
SELECT pg_size_pretty(pg_database_size(current_database()));
```

Symbol extraction is the slow one, and until it has run the public package
pages say so in as many words: "No advisory affecting *x* has had its symbols
extracted into this corpus." Loading advisories is not enough to make those
pages show anything, which is worth knowing before concluding that a fresh
load failed.

**It needs no GitHub token**, whatever `VEXPATH_GITHUB_TOKEN` suggests. It
clones with the `git` binary -- `git init --bare`, then a depth-2 fetch with
`--filter=blob:none` so only commits and trees come down and file contents are
read on demand -- and git fetches are not the API, so the sixty-requests-an-hour
limit for unauthenticated API calls has nothing to do with this job. Measured:
25 advisories in 72 seconds with no credentials of any kind.

What it is, is long. It is resumable precisely because no single run finishes,
and the backlog is thousands of advisories deep.

Until it has run, every scan reports `reach.analysed = false` -- "nobody
looked", which is deliberately not the same answer as "not reachable".

## Shipping a corpus you extracted somewhere else

Symbol extraction takes hours, so it runs where there is time for it -- a
laptop, a build box, anywhere -- and only the result is shipped. Measured on
2026-11-11: 55 passes of 200, about three hours, 2,641 advisories extracted,
37,727 symbols across 729 packages, 13.5% symbol coverage.

```sh
# Where the time goes. Resumable, so stopping costs the pass and not the run.
uv run python -m vexpath_worker.main extract-symbols --batch 200 \
  --cache-root var/patchcache          # repeat until a pass attempts 0

uv run python -m vexpath_worker.main export-snapshot var/snapshot-full
gzip -k var/snapshot-full/advisories.jsonl   # 62MB becomes 10MB
```

`read_snapshot` takes `advisories.jsonl.gz` when the plain file is absent, so
ship the compressed one. **Put it in a directory of its own**: if a plain
`advisories.jsonl` is present it wins, and an older corpus sitting next to the
new one would load instead of it, silently and with a valid hash.

```sh
# One line, because the machine stops five minutes after it starts.
curl -sS https://vexpath.fly.dev/healthz > /dev/null   # wake it
fly ssh console -c infra/fly.toml -C "mkdir -p /data/corpus"
# MSYS_NO_PATHCONV per command, not exported: see below for both halves of why.
MSYS_NO_PATHCONV=1 fly sftp put -c infra/fly.toml   var/snapshot-gz/snapshot.json /data/corpus/snapshot.json
MSYS_NO_PATHCONV=1 fly sftp put -c infra/fly.toml   var/snapshot-gz/advisories.jsonl.gz /data/corpus/advisories.jsonl.gz
fly ssh console -c infra/fly.toml -C "python -m vexpath_worker.main seed-advisories /data/corpus"
```

The load is one transaction, so a machine that stops part-way leaves the
corpus as it was. Run it again.

**On Git Bash, `export MSYS_NO_PATHCONV=1` is not optional.** MSYS rewrites an
argument that looks like a Unix path into a Windows one, so
`/data/corpus/snapshot.json` arrives as
`C:/Program Files/Git/data/corpus/snapshot.json` and the upload fails with
"file does not exist" naming a path you never typed. It only mangles a path
that stands alone as its own argument, which is why the `ssh -C "... /data/..."`
lines work without it and the `sftp put` lines do not.

**And set it per command rather than exporting it.** Exported, it also stops
`/dev/null` being translated, so a Windows `curl -o /dev/null` fails with
"client returned ERROR on write of 132 bytes" and takes the rest of an `&&`
chain with it. The conversion is load-bearing for `/dev/null` and wrong for
`/data`; turning it off globally just moves the breakage. A shell redirect
(`> /dev/null`) is handled by bash and is unaffected either way.

## The free allowance, and the five-minute machine

A Fly account with no card on file is a **trial**: machines are stopped after
five minutes, whatever `min_machines_running` says. The logs say so plainly —
`Trial machine stopping. To run for longer than 5m0s` — and it is not a
misconfiguration, so nothing in this repository can fix it.

The deployment still works, because `auto_start_machines` is on: a request to
a stopped machine starts it. The cost is a cold start on the first request
after an idle period, measured here at **4.8 seconds**, and health checks that
report nothing in between. Adding a card lifts the stop without being charged
for this shape of deployment — one shared-cpu machine and a 3GB volume sit
inside the free allowance.

Which to pick depends on what the deployment is for. A demo somebody opens
occasionally is fine with the cold start. Anything that is supposed to receive
a webhook, or to look healthy to an uptime monitor, is not: the machine is
stopped most of the time and a delivery to a stopped machine waits for it to
boot.

**It is not a limit on the corpus**, which is the question it looks like it
answers. Symbol extraction takes hours and the five-minute stop makes it
impossible *on Fly* -- but nothing requires it to run there. Extract locally,
where no clock applies, `export-snapshot` the result, and load that snapshot
into the live database in one short run. That is exactly the order
sync → extract → export already prescribes, and it is why the export step
exists at all.

## The advisory pipeline

The corpus is what makes a clearance possible, and it is built by four jobs in
a fixed order. **Without the export step the extracted symbols never reach the
tool that does the reaching**, and every piece works alone, so the omission is
easy to miss and invisible in a test.

```sh
# Daily: download advisories and attach EPSS and KEV.
fly machine run . -c infra/fly.toml --schedule daily --region sin \
  --volume vexpath_data:/data \
  --command "python -m vexpath_worker.main sync-advisories --ecosystem PyPI /data/advisories"

# Daily, after the sync: refresh the two feeds in place.
fly machine run . -c infra/fly.toml --schedule daily \
  --command "python -m vexpath_worker.main enrich-advisories"

# Hourly: diff fix commits into vulnerable symbols. Resumable, so a short run
# makes progress; the PyPI backlog is thousands of advisories.
fly machine run . -c infra/fly.toml --schedule hourly \
  --volume vexpath_data:/data \
  --command "python -m vexpath_worker.main extract-symbols --batch 200"

# Daily, last: write the enriched corpus back out for the scanner to read.
fly machine run . -c infra/fly.toml --schedule daily \
  --volume vexpath_data:/data \
  --command "python -m vexpath_worker.main export-snapshot /data/advisories"
```

The order that matters is sync → extract → export: without the export the
extracted symbols never reach the tool that does the reaching.

`VEXPATH_ADVISORY_SNAPSHOT_DIR` is read by **nothing at all**. Both the export
job and the seed job take the directory as a command argument, which is why
every command above names `/data/advisories` explicitly. The package pages are
built from the database, so an empty volume on a first deploy breaks nothing
either.

Three settings are like this — that one, `VEXPATH_GITHUB_TOKEN` and the
`VEXPATH_S3_*` group. They are declared, documented here as inert, and
`packages/platform/tests/test_settings.py` fails if that stops being true in
either direction: if one of them gains a reader, or if any other setting loses
its last one.

## Running it by hand

```sh
uvicorn vexpath_api.main:app --loop vexpath_platform.eventloop:event_loop_factory
```

**The `--loop` flag is not optional.** Since 0.36 uvicorn builds its event loop
from its own factory and ignores the installed policy; on Windows that factory
picks the proactor loop, which psycopg's asynchronous mode cannot use at all.
Without the flag the process looks healthy, `/readyz` reports the database
down, and every page that touches it fails. The Makefile, the Dockerfile and
the compose file all pass it; `make api` is the short version.

## Scaling, and the one thing that does not scale yet

`min_machines_running = 1`, and going past one machine needs a change first:
the rate limiter keeps its counters in the process, so two machines each allow
the configured rate. That is written down in
`packages/platform/src/vexpath_platform/ratelimit.py` rather than hidden, and
the fix is a shared counter in Postgres at the cost of a write per request —
worth doing when there is a second machine, not before.

Everything else is stateless. Sessions, keys and scans are in Postgres; the
snapshot and graph cache on the volume are rebuildable, so losing the volume
costs a cold scan (fourteen minutes instead of twelve seconds) rather than
data. Object storage is configured for but not yet used by anything, so there
is no third thing to back up.

## Rolling back

```sh
fly releases -c infra/fly.toml
fly deploy -c infra/fly.toml --image <previous image ref>
```

A rollback does **not** reverse a migration. Every migration in this
repository has a working `downgrade`, and they are tested in both directions,
but reversing one that dropped a column loses what was in it. The safe
sequence is: roll the image back first, then decide about the schema with the
old code already serving.

## Backups

Neon keeps point-in-time recovery; nothing here adds to that. What is worth
knowing is what cannot be recovered from a database backup alone: **API key
secrets and webhook signing secrets are not in it** — only hashes and
ciphertext — so a restore means re-issuing keys and rotating webhook secrets
rather than finding them in the dump. That is the intended trade, and it is the
reason a database disclosure hands over no working credentials.
