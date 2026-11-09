# sscp-api

One FastAPI application serving two audiences (ADR-0011):

- **`/v1/*` returns JSON.** Consumed by the `sscp` CLI, the GitHub Action, and anyone else. Specified in `docs/04-api-and-cli.md` and published as OpenAPI 3.1.
- **Everything else returns HTML.** Server-rendered Jinja2 templates with HTMX attributes for partial updates. No JavaScript is authored in this repository.

Both route groups call the same service layer, so the web page and the API response can never disagree about a finding.

## Running it

```bash
make api          # uvicorn with reload on http://localhost:8000
make up           # or the whole stack in Docker, including Postgres and MinIO
```

| Path | What it is |
|---|---|
| `/healthz` | Liveness. Returns 200 as long as the process is up. |
| `/readyz` | Readiness. Checks the database and reports degraded dependencies. |
| `/` | The HTML home page. |
| `/docs` | OpenAPI interactive documentation for the JSON API. |

## Layout

```
src/sscp_api/
├── main.py            application factory, middleware, router registration
├── settings.py        environment-driven configuration
├── logging.py         structlog setup, JSON in production, console locally
├── routers/
│   ├── health.py      /healthz and /readyz
│   └── pages.py       HTML routes
├── templates/         Jinja2 templates
└── static/            compiled stylesheet and the vendored HTMX asset
```

## Scope at this milestone

M0 delivers the application factory, settings, logging, health and readiness endpoints, the template layer and the home page. Authentication, projects, scans and findings arrive in M4, once there is something to store.
