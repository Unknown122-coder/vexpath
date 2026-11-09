# ADR-0011 · Server-rendered Python web UI inside the API application

Supersedes [ADR-0004](0004-nextjs-on-vercel.md).

## Context

The project is built and maintained by a Python developer who does not write JavaScript. A TypeScript front end would be the least maintainable part of the system for its owner, and the one most likely to rot. Meanwhile the actual UI requirements are modest:

- Public report and package pages: read-mostly, server-rendered, SEO-indexable. No client state at all.
- Dashboard: lists, a finding detail view with a call-path display, a policy editor with validation, API key management. Every interaction is a form submission or a partial refresh.
- A badge endpoint returning SVG.

None of that needs a client-side framework. It needs server-rendered HTML and partial updates.

## Decision

**One FastAPI application serves both the JSON API and the HTML UI.**

- `apps/api` contains two router groups: `/v1/*` returns JSON (consumed by the CLI, the Action and any third party), and `/*` returns HTML pages for humans. They share the same service layer, so there is no internal HTTP hop and no duplicated logic.
- Templates: **Jinja2**, with a base layout and partials. Rendering happens on the server, always.
- Interactivity: **HTMX** via `hx-*` attributes in the templates. Partial updates return HTML fragments from the same FastAPI handlers. No JavaScript files are authored in this repository; HTMX ships as a single vendored `.min.js` asset that we configure through markup only.
- Styling: **Tailwind CSS** compiled by the standalone Tailwind CLI binary, which requires no Node installation. The compiled stylesheet is committed so that a plain `pip install` deployment needs no asset build step.
- Charts and the call-path viewer: server-rendered inline SVG and HTML generated from the same `core.report` module the CLI uses.
- Documentation site: Markdown files in `docs/` rendered by the same app at `/docs` via a Jinja template and a Markdown library.
- End-to-end tests: **Playwright for Python**, driving a real browser. Playwright's Python bindings mean no JavaScript test code.

## Consequences

**Good**

- Single language, single deployment unit, single container. No CORS, no two-origin session handling, no separate preview environment.
- No Node, npm, pnpm, bundler, lockfile or `node_modules` anywhere in the repository or CI.
- The HTML UI reuses the `core` Pydantic models and `core.report` renderers directly, so the terminal report, the PR comment and the web page cannot drift apart.
- Server rendering gives the public pages ideal SEO characteristics with no framework work.

**Costs accepted**

- The UI will feel like a well-built server-rendered application, not a single-page app. For this product's audience (engineers reading reports) that is appropriate, not a compromise.
- Rich client interactions (a draggable graph explorer, for instance) are out of reach without JavaScript. The call-path viewer is therefore a server-rendered tree, which is sufficient and arguably clearer.
- Vercel is no longer used; the whole platform deploys as one container to Fly.io or Render. Postgres (Neon) and object storage (R2) are unchanged.
- The vendored HTMX asset is a third-party dependency to keep updated; it is pinned by version and hash like any other.

## Note on "no JavaScript"

HTMX is a JavaScript library, but it is consumed entirely through HTML attributes. No `.js` file in this repository is written or edited by hand. If even a vendored library is unwanted, the same templates work without HTMX using plain form submissions and full-page renders; HTMX only removes full-page reloads. This fallback is kept working by making every HTMX-driven action also valid as a normal form POST.
