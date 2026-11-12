"""Application factory.

One ASGI application serves the JSON API under ``/v1`` and the HTML UI
everywhere else (ADR-0011). Long-lived resources are created in the lifespan
handler so that a test can build an application with its own engine without
reaching into module globals.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from vexpath_api import __version__
from vexpath_api.oauth import IdentityProvider
from vexpath_api.observability import ForwardedSchemeMiddleware, RequestContextMiddleware
from vexpath_api.routers import (
    dashboard,
    evidence,
    findings,
    health,
    hooks_pages,
    login,
    me,
    pages,
    policy_ui,
    projects,
    public,
    scans,
    suppressions,
    webhooks,
)
from vexpath_api.session import RedirectRequired
from vexpath_api.templating import STATIC_DIR, build_templates
from vexpath_api.throttle import RateLimitMiddleware
from vexpath_db.engine import create_app_engine
from vexpath_platform.eventloop import configure_event_loop
from vexpath_platform.logging import configure_logging, get_logger
from vexpath_platform.settings import Settings, get_settings
from vexpath_platform.tracing import configure_sentry

log = get_logger(__name__)

#: Sent on every response. ``script-src 'self'`` is deliberate: the UI loads
#: only same-origin assets, so no inline script or third-party CDN is possible
#: even by accident (see docs/06-threat-model.md).
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
}

#: One year, subdomains included, and deliberately no ``preload``.
#:
#: Fly redirects http to https, but a redirect is only protection after the
#: first request: the one that arrives over plain http has already been sent,
#: and a session cookie or an API key in it is already gone. This header is
#: what stops the browser making that request a second time.
#:
#: ``preload`` is left off because it is a submission to a list baked into
#: browser binaries, and removal takes months. Claiming it in a header while
#: not being on the list is a lie; being on it is a decision about every
#: future subdomain, which is not one to take by default.
STRICT_TRANSPORT_SECURITY = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach the security headers to every response.

    Args:
        hsts: Whether to send ``Strict-Transport-Security``. Off unless the
            deployment is actually served over https, because a browser that
            is told to pin ``localhost`` to https honours it for a year --
            for every project on that machine, not just this one, and with no
            obvious way back.
    """

    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        super().__init__(app)
        self._hsts = hsts

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if self._hsts:
            response.headers.setdefault("Strict-Transport-Security", STRICT_TRANSPORT_SECURITY)
        return response


def create_app(
    settings: Settings | None = None,
    *,
    engine: AsyncEngine | None = None,
    identity_provider: IdentityProvider | None = None,
) -> FastAPI:
    """Build the ASGI application.

    Args:
        settings: Configuration to use. Defaults to the process environment.
        engine: An existing engine to adopt, which lets tests supply their own
            database without the lifespan creating a second one.
        identity_provider: Sign-in provider to use instead of the one built
            from configuration. The injection point that makes every branch
            of the sign-in flow reachable without a network, including the
            failures, which are the ones that otherwise answer 500 the first
            time a real user meets them.
    """
    resolved = settings or get_settings()
    configure_logging(resolved)
    # Before the application exists, so an error raised while building it
    # is reported too. Returns whether it started, which is said once at
    # start-up rather than left for an operator to guess.
    reporting = configure_sentry(resolved)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owns_engine = engine is None
        app.state.engine = engine or create_app_engine(
            resolved.database_url, echo=resolved.database_echo
        )
        log.info(
            "api.start",
            version=__version__,
            environment=resolved.env.value,
            owns_engine=owns_engine,
            error_reporting=reporting,
        )
        try:
            yield
        finally:
            if owns_engine:
                await app.state.engine.dispose()
            log.info("api.stop")

    app = FastAPI(
        title="Software Supply-Chain Security Platform",
        summary="Reachability-aware vulnerability analysis with signed VEX output.",
        version=__version__,
        docs_url=resolved.docs_url,
        redoc_url=None,
        # Served everywhere, unlike the interactive explorer above. The
        # document is public API documentation -- it is committed to this
        # repository -- and withholding it only stops people generating a
        # client. Swagger UI stays off in production because it needs a
        # third-party script this site's CSP refuses; the reference page at
        # /api is rendered on the server from this same schema.
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    app.state.settings = resolved
    app.state.templates = build_templates(resolved)
    app.state.identity_provider = identity_provider
    app.add_middleware(SecurityHeadersMiddleware, hsts=resolved.base_url.startswith("https://"))
    # Added after, so it runs before: Starlette applies middleware in
    # reverse order of registration, and a refusal should cost as little
    # as possible.
    app.add_middleware(
        RateLimitMiddleware,
        trust_proxy_headers=resolved.trust_proxy_headers,
        enabled=resolved.rate_limit_enabled,
    )
    # Outermost, because every other middleware's log lines should carry
    # the request id -- including a rate-limit refusal, which is the one
    # somebody will ask about.
    app.add_middleware(RequestContextMiddleware, trust_proxy_headers=resolved.trust_proxy_headers)
    # Last registered, so it runs first: everything above reads the scheme,
    # and behind a TLS-terminating proxy the scheme on the connection is a
    # lie. See ForwardedSchemeMiddleware for what that cost.
    app.add_middleware(ForwardedSchemeMiddleware, trust_proxy_headers=resolved.trust_proxy_headers)

    @app.exception_handler(RedirectRequired)
    async def _redirect(request: Request, exc: RedirectRequired) -> Response:
        """Send a browser somewhere else.

        Raised by the session guards, which run as dependencies and so
        cannot return a response. A 401 with a JSON body is the right
        answer to a mis-authenticated API call and a dead end for a person
        who needs to sign in.
        """
        del request
        return RedirectResponse(exc.location, status_code=exc.status_code)

    # JSON API. Every one of these obtains its database connection through a
    # dependency that authenticates and scopes in the same step, so there is
    # no arrangement of them that yields an authenticated, unscoped request.
    app.include_router(health.router)
    app.include_router(projects.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(suppressions.router)
    app.include_router(webhooks.router)
    app.include_router(me.router)

    # Sign-in and the signed-in pages. Cookie-authenticated, and the only
    # routes that are: /v1 refuses cookies so no endpoint there inherits
    # the cross-site request forgery problem a browser credential brings.
    app.include_router(login.router)
    app.include_router(dashboard.router)
    # Before evidence: its project page matches a path-converted slug, which
    # would otherwise swallow "{slug}/policy" and render a project called
    # "svc/policy". The more specific route has to be registered first.
    app.include_router(policy_ui.router)
    app.include_router(evidence.router)
    app.include_router(hooks_pages.router)

    # HTML UI. Registered last so its catch-all routes cannot shadow /v1.
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    # Public pages take a connection with no tenant context, so a bug in one
    # of them produces an empty page rather than another organisation's data.
    app.include_router(public.router)
    app.include_router(pages.router)

    return app


# Windows defaults to an event loop psycopg's asynchronous mode cannot use.
# Done here, before the application exists, because the policy is process-wide
# and create_app must not have side effects of that kind.
configure_event_loop()

#: Module-level application for ``uvicorn vexpath_api.main:app``.
app = create_app()


__all__ = ["SECURITY_HEADERS", "app", "create_app"]
