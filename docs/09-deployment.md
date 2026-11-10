# 09 · Deployment

One container image, three things it can be: the API and HTML UI, the advisory
pipeline on a schedule, and the migration runner. Postgres is managed (Neon),
object storage is S3-compatible (Cloudflare R2), and nothing else is required.

This document is the runbook. It is written so that somebody who has never
deployed this can do it, and so that somebody who has can tell whether it is
healthy.

## What has to exist first

| Thing | Why |
|---|---|
| A Fly.io account and `flyctl` | The host. Render works the same way; the `fly.toml` here is the one that is maintained. |
| A Neon Postgres database | Everything structured, including the job queue (ADR-0003). |
| A Cloudflare R2 bucket | SBOMs, VEX documents and attestations. |
| A GitHub OAuth app | Sign-in. Callback URL **must** be `<base-url>/auth/github/callback`. |
| A GitHub token (classic, no scopes) | Raises the API rate limit for patch diffing. Optional but the extraction crawl is slow without it. |

## Secrets

Set with `fly secrets set`, which stores them encrypted and keeps them out of
this repository and out of every image layer. None of these has a default
outside local development: a missing secret fails at start-up rather than
falling back to something insecure.

```sh
fly secrets set \
  VEXPATH_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  VEXPATH_DATABASE_URL='postgresql+psycopg://…neon.tech/vexpath?sslmode=require' \
  VEXPATH_GITHUB_CLIENT_ID=… \
  VEXPATH_GITHUB_CLIENT_SECRET=… \
  VEXPATH_GITHUB_TOKEN=… \
  VEXPATH_S3_ENDPOINT_URL='https://<account>.r2.cloudflarestorage.com' \
  VEXPATH_S3_ACCESS_KEY_ID=… \
  VEXPATH_S3_SECRET_ACCESS_KEY=… \
  VEXPATH_SENTRY_DSN=…   # optional
```

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
fly volumes create vexpath_data --region lhr --size 20
fly secrets set …                      # above
fly deploy -c infra/fly.toml
```

The deploy runs `alembic upgrade head` as a release command **before** any new
machine takes traffic. If it fails the deploy stops, which is intended: code
that expects a column must not serve requests before that column exists.

## After the deploy, check these four things

```sh
curl -fsS https://vexpath.dev/healthz   # the process is alive
curl -fsS https://vexpath.dev/readyz    # it can reach the database
curl -fsSo /dev/null -w '%{http_code}\n' https://vexpath.dev/login   # 200
fly logs -c infra/fly.toml | head -20   # one JSON line per request
```

`/readyz` answering 503 while `/healthz` answers 200 means the process is fine
and the database is not — that pairing is deliberate, so a database outage
stops traffic reaching a machine without restarting it in a loop.

Then sign in once. If the GitHub callback URL is wrong, the sign-in page says
so rather than failing silently; if the OAuth credentials are absent, it says
sign-in is not configured.

## The advisory pipeline

The corpus is what makes a clearance possible, and it is built by four jobs in
a fixed order. **Without the export step the extracted symbols never reach the
tool that does the reaching**, and every piece works alone, so the omission is
easy to miss and invisible in a test.

```sh
# Daily: download advisories and attach EPSS and KEV.
fly machine run . -c infra/fly.toml --schedule daily --region lhr \
  --volume vexpath_data:/data \
  --command "python -m vexpath_worker.main sync-advisories --ecosystem PyPI"

# Daily, after the sync: refresh the two feeds in place.
fly machine run . -c infra/fly.toml --schedule daily \
  --command "python -m vexpath_worker.main enrich-advisories"

# Hourly: diff fix commits into vulnerable symbols. Resumable, so a short run
# makes progress; the PyPI backlog is thousands of advisories.
fly machine run . -c infra/fly.toml --schedule hourly \
  --volume vexpath_data:/data \
  --command "python -m vexpath_worker.main extract-symbols --limit 200"

# Daily, last: write the enriched corpus back out for the scanner to read.
fly machine run . -c infra/fly.toml --schedule daily \
  --volume vexpath_data:/data \
  --command "python -m vexpath_worker.main export-snapshot /data/advisories"
```

The order that matters is sync → extract → export. `VEXPATH_ADVISORY_SNAPSHOT_DIR`
points the API at the exported snapshot so the package pages and any
server-side matching read the same corpus the command line does.

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

Everything else is stateless. Sessions, keys and scans are in Postgres;
artefacts are in R2; the snapshot and graph cache on the volume are
rebuildable, so losing the volume costs a cold scan (fourteen minutes instead
of twelve seconds) rather than data.

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
