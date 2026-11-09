# ADR-0004 · Next.js on Vercel for the web app and public pages

**Status: superseded by [ADR-0011](0011-server-rendered-python-web.md) on 2026-11-09.**

The original decision was Next.js (App Router, TypeScript, Tailwind) on Vercel, with the web app as a client of the FastAPI service.

It was superseded because the project is maintained by a Python-only developer. A TypeScript front end would be unmaintainable for its owner, which is a worse outcome than any rendering benefit it offers. ADR-0011 records the replacement: server-rendered Jinja2 templates inside the FastAPI application.
