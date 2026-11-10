"""The rate-limiting middleware: who is counted, and against which rule.

Two questions, and the first one is where rate limiters usually go wrong.

**Who is this?** In order: the API key (by a prefix of its hash, never the key
itself), then the session, then the client address. The address is read from
the socket unless this deployment is explicitly configured to trust a proxy
header, because `X-Forwarded-For` is a request header like any other: anybody
can send one. Trusting it unconditionally would let a caller evade their own
limit by varying it, and — worse — exhaust somebody else's bucket by claiming
their address.

**Which rule?** Writes are limited harder than reads because they cost more
and matter more, and the sign-in flow harder still: it is the one path that
creates rows for an unauthenticated caller. The public pages get their own,
generous rule, because a badge in a popular README is meant to be fetched a
lot and a limiter that broke that would be the limiter breaking the product.

Health checks are never limited. A liveness probe that gets a 429 takes the
instance out of service, which turns a rate limiter into an outage.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from vexpath_platform import sessions as session_tokens
from vexpath_platform.apikeys import bearer_token
from vexpath_platform.logging import get_logger
from vexpath_platform.ratelimit import Limiter, Rule, identity_from_key

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Rules:
    """The rules, in one object so a deployment can see all of them at once.

    Deliberately generous. A limiter exists here to stop a runaway loop and a
    scraper, not to meter a product, and one tight enough to interrupt honest
    use would cost more than the traffic it refused.
    """

    #: Reads of the JSON API.
    read: Rule = field(default_factory=lambda: Rule(limit=600, window_seconds=60))
    #: Writes: uploads, project creation, suppressions.
    write: Rule = field(default_factory=lambda: Rule(limit=60, window_seconds=60))
    #: The sign-in flow. The only path where an unauthenticated caller causes
    #: rows to be written, so it is the one worth holding down.
    sign_in: Rule = field(default_factory=lambda: Rule(limit=20, window_seconds=300))
    #: Public report pages and badges. A badge in a busy README is meant to be
    #: fetched often; a limiter that broke that would be breaking the product.
    public: Rule = field(default_factory=lambda: Rule(limit=1200, window_seconds=60))


#: Paths that are never limited. A liveness probe answered with 429 takes the
#: instance out of service, which turns a rate limiter into an outage.
EXEMPT_PREFIXES = ("/healthz", "/readyz", "/static")

#: Methods that change something.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Count each request and refuse the ones over the line."""

    def __init__(
        self,
        app: object,
        *,
        limiter: Limiter | None = None,
        rules: Rules | None = None,
        trust_proxy_headers: bool = False,
        enabled: bool = True,
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.limiter = limiter or Limiter()
        self.rules = rules or Rules()
        self.trust_proxy_headers = trust_proxy_headers
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self.enabled or request.url.path.startswith(EXEMPT_PREFIXES):
            return await call_next(request)

        bucket, rule = self._rule(request)
        decision = self.limiter.check(f"{bucket}:{self._identity(request)}", rule)
        if not decision.allowed:
            log.info("api.ratelimit.refused", bucket=bucket, path=request.url.path)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": (
                        f"too many requests: at most {decision.limit} per "
                        f"{rule.window_seconds} seconds for this kind of request"
                    )
                },
                headers={
                    # A real number of seconds, not an estimate: a client that
                    # obeys a wrong one either hammers or stalls.
                    "Retry-After": str(decision.retry_after),
                    "X-RateLimit-Limit": str(decision.limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers.setdefault("X-RateLimit-Limit", str(decision.limit))
        response.headers.setdefault("X-RateLimit-Remaining", str(decision.remaining))
        return response

    def _rule(self, request: Request) -> tuple[str, Rule]:
        path = request.url.path
        if path.startswith(("/auth/", "/login")):
            return "sign_in", self.rules.sign_in
        if path.startswith(("/p/", "/badge/", "/package/")):
            return "public", self.rules.public
        if request.method in WRITE_METHODS:
            return "write", self.rules.write
        return "read", self.rules.read

    def _identity(self, request: Request) -> str:
        """Who to count this against.

        The credential first, so one organisation's runaway job cannot consume
        another organisation's allowance merely by sharing an address — which
        is the normal case behind corporate network address translation and a
        shared CI runner.
        """
        token = bearer_token(request.headers.get("authorization"))
        if token:
            # Never the key itself. This value ends up in a counter table that
            # a heap profile would show.
            return f"key/{identity_from_key(token)}"

        cookie = request.cookies.get(session_tokens.COOKIE_NAME)
        if cookie:
            return f"session/{session_tokens.hash_token(cookie)[:16]}"

        return f"address/{self._address(request)}"

    def _address(self, request: Request) -> str:
        """The client's address, from the socket unless a proxy is trusted.

        ``X-Forwarded-For`` is a request header: anybody can send one.
        Trusting it unconditionally lets a caller evade their own limit by
        varying it, and lets them exhaust somebody else's bucket by claiming
        their address. So it is used only where a deployment says there is a
        proxy in front, and then only its last hop, which is the one that
        proxy wrote.
        """
        if self.trust_proxy_headers:
            forwarded = request.headers.get("x-forwarded-for", "")
            hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
            if hops:
                return hops[-1]
        client = request.client
        return client.host if client is not None else "unknown"


__all__ = ["EXEMPT_PREFIXES", "WRITE_METHODS", "RateLimitMiddleware", "Rules"]
