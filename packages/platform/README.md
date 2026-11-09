# sscp-platform

Concerns that the API and the workers both have, and that neither should own.

Without this package the choices are to duplicate configuration in two places or to make the worker import the web framework. Both are worse.

| Module | Purpose |
|---|---|
| `settings` | Environment-driven configuration, one `SSCP_`-prefixed variable per setting, documented in `.env.example` |
| `logging` | structlog setup: JSON when deployed, colour locally, with central redaction of fields that must never be logged |

## What does not belong here

Anything that decides a verdict. That lives in `sscp-core`, which has no configuration and no logging setup of its own, because an analysis result must not depend on how the process was configured.

Object storage access will join this package when the first artefact is written (M3), for the same reason settings did: the API and the workers both need it.
