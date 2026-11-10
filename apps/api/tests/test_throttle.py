"""The rate-limiting middleware.

Tested against a minimal application rather than the real one, so these run
without a database and so the rules can be tight enough to cross in a test
without pretending the production limits are tight.

The assertion that matters most is the one about ``X-Forwarded-For``. That
header is a request header like any other: if it is believed without a proxy
in front, a caller evades their own limit by varying it, and — worse —
exhausts somebody else's allowance by claiming their address. Off by default,
and a test says so.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from vexpath_api.throttle import RateLimitMiddleware, Rules
from vexpath_platform.ratelimit import Limiter, Rule


def build(**kwargs: object) -> TestClient:
    app = FastAPI()

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/things")
    async def read() -> dict[str, str]:
        return {"ok": "read"}

    @app.post("/v1/things")
    async def write() -> dict[str, str]:
        return {"ok": "write"}

    @app.get("/badge/org/project.svg")
    async def badge() -> dict[str, str]:
        return {"ok": "badge"}

    @app.get("/auth/github/start")
    async def start() -> dict[str, str]:
        return {"ok": "start"}

    rules = Rules(
        read=Rule(limit=3, window_seconds=60),
        write=Rule(limit=2, window_seconds=60),
        sign_in=Rule(limit=1, window_seconds=60),
        public=Rule(limit=5, window_seconds=60),
    )
    app.add_middleware(RateLimitMiddleware, limiter=Limiter(), rules=rules, **kwargs)
    return TestClient(app)


def test_requests_under_the_limit_pass_with_their_allowance_in_a_header() -> None:
    client = build()
    response = client.get("/v1/things")
    assert response.status_code == 200
    assert response.headers["X-RateLimit-Limit"] == "3"
    assert response.headers["X-RateLimit-Remaining"] == "2"


def test_crossing_the_limit_answers_429_with_a_retry_after() -> None:
    client = build()
    for _ in range(3):
        assert client.get("/v1/things").status_code == 200
    refused = client.get("/v1/things")
    assert refused.status_code == 429
    assert 1 <= int(refused.headers["Retry-After"]) <= 60
    # The message says what the limit is, so a CI job's log explains itself.
    assert "at most 3 per 60 seconds" in refused.json()["detail"]


def test_writes_are_limited_harder_than_reads() -> None:
    client = build()
    assert client.post("/v1/things").status_code == 200
    assert client.post("/v1/things").status_code == 200
    # Writes cost more and matter more.
    assert client.post("/v1/things").status_code == 429
    # A separate bucket, so a used-up write allowance does not block reading.
    assert client.get("/v1/things").status_code == 200


def test_the_sign_in_flow_has_its_own_tighter_bucket() -> None:
    client = build()
    assert client.get("/auth/github/start").status_code == 200
    # The one path where an unauthenticated caller causes rows to be written.
    assert client.get("/auth/github/start").status_code == 429


def test_the_public_pages_get_a_generous_bucket_of_their_own() -> None:
    client = build()
    for _ in range(5):
        assert client.get("/badge/org/project.svg").status_code == 200
    # A badge in a busy README is meant to be fetched often; the limit exists
    # but it is not the one that applies to the API.
    assert client.get("/badge/org/project.svg").status_code == 429


def test_health_checks_are_never_limited() -> None:
    client = build()
    for _ in range(50):
        assert client.get("/healthz").status_code == 200
    # A liveness probe answered with 429 takes the instance out of service,
    # which turns a rate limiter into an outage.


def test_two_api_keys_are_counted_separately() -> None:
    client = build()
    first = {"Authorization": "Bearer vexpath_live_" + "a" * 43}
    second = {"Authorization": "Bearer vexpath_live_" + "b" * 43}
    for _ in range(3):
        assert client.get("/v1/things", headers=first).status_code == 200
    assert client.get("/v1/things", headers=first).status_code == 429
    # One organisation's runaway job must not consume another's allowance,
    # which is the normal case behind a shared CI runner or office network.
    assert client.get("/v1/things", headers=second).status_code == 200


def test_a_forwarded_header_is_ignored_unless_a_proxy_is_trusted() -> None:
    client = build()
    for index in range(3):
        assert (
            client.get("/v1/things", headers={"X-Forwarded-For": f"10.0.0.{index}"}).status_code
            == 200
        )
    # Varying a header anybody can send must not reset the counter: that is
    # the difference between a limiter and a formality.
    assert client.get("/v1/things", headers={"X-Forwarded-For": "10.0.0.99"}).status_code == 429


def test_a_trusted_proxy_header_is_believed_when_configured() -> None:
    client = build(trust_proxy_headers=True)
    for index in range(4):
        response = client.get("/v1/things", headers={"X-Forwarded-For": f"10.0.0.{index}"})
        # Four distinct clients behind a proxy, each under the limit of three.
        assert response.status_code == 200, index


def test_only_the_last_hop_of_a_forwarded_chain_is_used() -> None:
    client = build(trust_proxy_headers=True)
    # The last hop is the one the trusted proxy wrote; the earlier entries
    # came from the client and are no more trustworthy than the header itself.
    for _ in range(3):
        assert (
            client.get(
                "/v1/things", headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.7"}
            ).status_code
            == 200
        )
    assert (
        client.get("/v1/things", headers={"X-Forwarded-For": "9.9.9.9, 198.51.100.7"}).status_code
        == 429
    )


def test_the_limiter_can_be_turned_off() -> None:
    client = build(enabled=False)
    for _ in range(20):
        assert client.get("/v1/things").status_code == 200
    # No headers either, so nothing claims a limit that is not being applied.
    assert "X-RateLimit-Limit" not in client.get("/v1/things").headers
