"""Request correlation and the access log.

One line per request, after it finishes, carrying the request id, method, path
template, status and duration. One line rather than two: a start line plus an
end line doubles the volume to make hung requests visible, and a hung request
is already visible as a missing line next to a client complaining. What a
start line would have added, the request id gives for free — every log line
emitted *during* the request carries it, because it is bound into a context
variable rather than passed down through call signatures.

**The path template, not the path.** `/app/findings/01JABC…` and
`/app/findings/01JXYZ…` are the same route, and a log keyed on the literal
path cannot answer "how slow is the finding page" without a regular
expression. The literal path is not logged at all: a slug or an advisory
identifier in a URL is tenant data, and the threat model keeps tenant data out
of the logs.

**An inbound request id is accepted only from a trusted proxy, and sanitised
either way.** This value is echoed into every log line for the request, so an
unsanitised one is log injection: a newline in it writes a second, forged line
into the stream somebody reads during an incident.

**The response carries the id back.** A user quoting it in a bug report is the
difference between a five-minute search and an afternoon of guessing.
"""

from __future__ import annotations

import re
import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from vexpath_platform.logging import get_logger

log = get_logger("vexpath_api.access")

#: Sent on the response, and read from the request where a proxy is trusted.
REQUEST_ID_HEADER = "X-Request-ID"

#: An inbound id is cut to this. Long enough for a UUID or a trace id, short
#: enough that nobody can pad a log line out of readability.
MAX_REQUEST_ID = 64

#: What an id may contain. Deliberately narrow: this value is written into
#: every log line for the request, and a newline in it forges a second line
#: into the stream somebody reads during an incident.
_SAFE_ID = re.compile(r"[A-Za-z0-9._:-]+")

#: Paths that are not logged. A liveness probe every fifteen seconds is the
#: single noisiest thing in the log and says nothing when it succeeds.
QUIET_PREFIXES = ("/healthz", "/readyz", "/static")

#: Above this, a request is logged at warning level. Not an alert threshold --
#: it is a marker so the slow ones are findable without a query language.
SLOW_SECONDS = 2.0


class ForwardedSchemeMiddleware:
    """Believe ``X-Forwarded-Proto`` when a proxy terminates TLS.

    Pure ASGI rather than ``BaseHTTPMiddleware`` and installed outermost,
    because this has to be true before anything downstream reads the scheme:
    ``url_for`` builds absolute URLs from it, and so do redirects.

    Without it the application behind Fly sees ``http``, because that is what
    the connection from the edge actually is. The consequence was not subtle
    and took a day to notice: every page emitted
    ``<link rel="stylesheet" href="http://...">`` while being served over
    https, browsers refuse a stylesheet loaded that way as mixed content, and
    the site's own Content-Security-Policy refused it too -- ``style-src
    'self'`` does not match a different scheme. So every visitor got the HTML
    with none of the design, and nothing anywhere said so: the page was 200,
    the stylesheet was 200 to anything that asked for it directly, and only a
    browser's console knew.

    Gated on the same setting as the client address, and off by default for
    the same reason: a caller who can reach the application directly could
    otherwise claim any scheme they liked.
    """

    def __init__(self, app: ASGIApp, *, trust_proxy_headers: bool = False) -> None:
        self.app = app
        self.trust_proxy_headers = trust_proxy_headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and self.trust_proxy_headers:
            for name, value in scope.get("headers", ()):
                if name == b"x-forwarded-proto":
                    # Only the two schemes this serves. A header saying
                    # anything else is a caller playing games, not a proxy.
                    forwarded = value.decode("latin-1").split(",")[0].strip().lower()
                    if forwarded in ("http", "https"):
                        scope["scheme"] = forwarded
                    break
        await self.app(scope, receive, send)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Bind a request id, time the request, and log one line when it ends."""

    def __init__(self, app: object, *, trust_proxy_headers: bool = False) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.trust_proxy_headers = trust_proxy_headers

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = self._request_id(request)
        # Cleared first. Contextvars survive in a reused worker task, so
        # without this a request with no id of its own would inherit the
        # previous one's -- which is worse than having none, because it reads
        # as evidence that two unrelated things happened together.
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        request.state.request_id = request_id

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration = time.perf_counter() - started
            # Logged here and re-raised: the exception handler sees it next,
            # and without this line an unhandled error would leave only a
            # traceback with no request id to tie it to anything.
            log.exception(
                "api.request.failed",
                method=request.method,
                route=self._route(request),
                duration_ms=round(duration * 1000, 1),
            )
            structlog.contextvars.clear_contextvars()
            raise

        duration = time.perf_counter() - started
        response.headers[REQUEST_ID_HEADER] = request_id

        if not request.url.path.startswith(QUIET_PREFIXES):
            emit = log.warning if duration >= SLOW_SECONDS else log.info
            emit(
                "api.request",
                method=request.method,
                # The template, not the literal path: two findings are the same
                # route, and a slug in a URL is tenant data.
                route=self._route(request),
                status=response.status_code,
                duration_ms=round(duration * 1000, 1),
            )

        # Cleared on the way out as well as in: a task returned to the pool
        # holding a stale request id would label the next request's lines with
        # the previous request's id.
        structlog.contextvars.clear_contextvars()
        return response

    def _request_id(self, request: Request) -> str:
        """The id for this request.

        An inbound one is honoured only behind a trusted proxy, for the same
        reason ``X-Forwarded-For`` is: it is a request header, so anybody can
        send one, and an attacker who can choose it can make their requests
        share an id with somebody else's.
        """
        if self.trust_proxy_headers:
            presented = request.headers.get(REQUEST_ID_HEADER, "")
            cleaned = _sanitise(presented)
            if cleaned:
                return cleaned
        return uuid.uuid4().hex

    def _route(self, request: Request) -> str:
        """The matched route's path template, or a placeholder.

        ``request.scope["route"]`` is set by the router, so it exists for a
        matched request and not for a 404 -- which is itself worth
        distinguishing, because a flood of unmatched paths is somebody
        scanning.
        """
        route = request.scope.get("route")
        path = getattr(route, "path", None)
        if isinstance(path, str):
            return path
        return "<unmatched>"


def _sanitise(value: str) -> str:
    """The acceptable part of a presented request id, or empty."""
    pieces = _SAFE_ID.findall(value.strip())
    if not pieces:
        return ""
    return "".join(pieces)[:MAX_REQUEST_ID]


__all__ = [
    "MAX_REQUEST_ID",
    "QUIET_PREFIXES",
    "REQUEST_ID_HEADER",
    "SLOW_SECONDS",
    "ForwardedSchemeMiddleware",
    "RequestContextMiddleware",
]
