"""Request correlation and the access log.

Against a minimal application, so these need no database and the log can be
captured without a real request flowing through twenty routes.

Two assertions carry the weight.

**A presented request id is not trusted unless a proxy is configured, and is
sanitised either way.** The id is written into every log line for the request,
so a newline in it forges a second line into the stream somebody reads during
an incident — and an attacker who can choose the id can make their requests
share one with somebody else's.

**The route template is logged, never the literal path.** A slug or an
advisory identifier in a URL is tenant data, and the threat model keeps tenant
data out of the logs. It is also the only form that answers "how slow is the
finding page" without a regular expression.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import structlog
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from vexpath_api import observability
from vexpath_api.observability import REQUEST_ID_HEADER


class Recorder:
    """Collects log calls together with whatever context was bound.

    A recorder rather than a structlog capture processor, because structlog
    caches a bound logger on first use: by the time this module runs inside
    the whole suite, the access logger has already been frozen with the
    application's own processors and reconfiguring structlog would not reach
    it. Reading the context variables directly tests the same thing without
    depending on test ordering.
    """

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def _record(self, level: str, event: str, **fields: Any) -> None:
        self.events.append(
            {
                "event": event,
                "level": level,
                **structlog.contextvars.get_contextvars(),
                **fields,
            }
        )

    def info(self, event: str, **fields: Any) -> None:
        self._record("info", event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._record("warning", event, **fields)

    def exception(self, event: str, **fields: Any) -> None:
        self._record("error", event, **fields)


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture what the middleware logs, for one test."""
    recorder = Recorder()
    monkeypatch.setattr(observability, "log", recorder)
    return recorder.events


def build(captured: list[dict[str, Any]], **kwargs: object) -> TestClient:
    app = FastAPI()

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/things/{thing_id}")
    async def read(thing_id: str) -> dict[str, str]:
        # Logged from inside the handler, through the same recorder, to show
        # the request id reaches code that was never passed one.
        captured.append(
            {"event": "handler.ran", **structlog.contextvars.get_contextvars(), "thing": thing_id}
        )
        return {"id": thing_id}

    @app.get("/boom")
    async def boom() -> dict[str, str]:
        msg = "deliberate"
        raise RuntimeError(msg)

    app.add_middleware(observability.RequestContextMiddleware, **kwargs)
    return TestClient(app, raise_server_exceptions=False)


def _access(events: list[dict[str, Any]]) -> dict[str, Any]:
    lines = [event for event in events if event.get("event") == "api.request"]
    assert len(lines) == 1, [event.get("event") for event in events]
    return lines[0]


def test_a_request_gets_an_id_and_gets_it_back(captured: list[dict[str, Any]]) -> None:
    response = build(captured).get("/v1/things/abc")
    assert response.status_code == 200
    # Echoed back so a user quoting it in a bug report turns an afternoon of
    # guessing into a five-minute search.
    assert response.headers[REQUEST_ID_HEADER]
    assert _access(captured)["request_id"] == response.headers[REQUEST_ID_HEADER]


def test_every_line_during_the_request_carries_the_same_id(
    captured: list[dict[str, Any]],
) -> None:
    response = build(captured).get("/v1/things/abc")
    request_id = response.headers[REQUEST_ID_HEADER]
    handler = next(event for event in captured if event.get("event") == "handler.ran")
    # Bound into a context variable rather than threaded through call
    # signatures, which is what makes this true of code that was never told
    # about it.
    assert handler["request_id"] == request_id


def test_two_requests_do_not_share_an_id(captured: list[dict[str, Any]]) -> None:
    client = build(captured)
    first = client.get("/v1/things/a").headers[REQUEST_ID_HEADER]
    second = client.get("/v1/things/b").headers[REQUEST_ID_HEADER]
    assert first != second
    # And the context does not leak between them: a stale id would read as
    # evidence that two unrelated things happened together.
    ids = {event["request_id"] for event in captured if "request_id" in event}
    assert ids == {first, second}


def test_the_route_template_is_logged_and_not_the_path(
    captured: list[dict[str, Any]],
) -> None:
    build(captured).get("/v1/things/01JSECRETSLUG")
    line = _access(captured)
    assert line["route"] == "/v1/things/{thing_id}"
    # A slug or an advisory identifier in a URL is tenant data.
    assert "01JSECRETSLUG" not in json.dumps(line)


def test_an_unmatched_path_is_distinguishable(captured: list[dict[str, Any]]) -> None:
    build(captured).get("/nope/nothing-here")
    # Worth telling apart: a flood of unmatched paths is somebody scanning.
    assert _access(captured)["route"] == "<unmatched>"


def test_the_duration_and_status_are_recorded(captured: list[dict[str, Any]]) -> None:
    build(captured).get("/v1/things/abc")
    line = _access(captured)
    assert line["status"] == 200
    assert line["method"] == "GET"
    assert isinstance(line["duration_ms"], float)


def test_health_checks_are_not_logged(captured: list[dict[str, Any]]) -> None:
    build(captured).get("/healthz")
    # A probe every fifteen seconds is the noisiest thing in the log and says
    # nothing when it succeeds.
    assert [event for event in captured if event.get("event") == "api.request"] == []


def test_an_unhandled_error_is_logged_with_its_request_id(
    captured: list[dict[str, Any]],
) -> None:
    build(captured).get("/boom")
    failed = [event for event in captured if event.get("event") == "api.request.failed"]
    assert len(failed) == 1
    # Without this line an unhandled error leaves a traceback with no request
    # id to tie it to anything the user did.
    assert failed[0]["request_id"]
    assert failed[0]["route"] == "/boom"


# --- A presented id ---------------------------------------------------------


def test_a_presented_id_is_ignored_without_a_trusted_proxy(
    captured: list[dict[str, Any]],
) -> None:
    response = build(captured).get(
        "/v1/things/a", headers={REQUEST_ID_HEADER: "chosen-by-the-caller"}
    )
    # Anybody can send a header. An attacker who can choose the id can make
    # their requests share one with somebody else's.
    assert response.headers[REQUEST_ID_HEADER] != "chosen-by-the-caller"


def test_a_presented_id_is_honoured_behind_a_trusted_proxy(
    captured: list[dict[str, Any]],
) -> None:
    client = build(captured, trust_proxy_headers=True)
    response = client.get("/v1/things/a", headers={REQUEST_ID_HEADER: "trace-abc-123"})
    # So a request can be followed across the proxy and this service.
    assert response.headers[REQUEST_ID_HEADER] == "trace-abc-123"
    assert _access(captured)["request_id"] == "trace-abc-123"


def test_a_presented_id_cannot_forge_a_log_line(captured: list[dict[str, Any]]) -> None:
    client = build(captured, trust_proxy_headers=True)
    forged = 'a\n{"event": "api.signin.ok", "user": "admin"}'
    response = client.get("/v1/things/a", headers={REQUEST_ID_HEADER: forged})
    recorded = response.headers[REQUEST_ID_HEADER]
    # The id is written into every line for the request, so a newline in it
    # would write a second, forged line into the stream somebody reads during
    # an incident.
    assert "\n" not in recorded
    assert "{" not in recorded
    assert '"' not in recorded


def test_an_absurdly_long_presented_id_is_cut(captured: list[dict[str, Any]]) -> None:
    client = build(captured, trust_proxy_headers=True)
    response = client.get("/v1/things/a", headers={REQUEST_ID_HEADER: "x" * 5000})
    # Nobody pads a log line out of readability.
    assert len(response.headers[REQUEST_ID_HEADER]) <= 64


def test_an_empty_presented_id_falls_back_to_a_generated_one(
    captured: list[dict[str, Any]],
) -> None:
    client = build(captured, trust_proxy_headers=True)
    response = client.get("/v1/things/a", headers={REQUEST_ID_HEADER: "   "})
    assert response.headers[REQUEST_ID_HEADER].strip()


# --- The scheme behind a proxy --------------------------------------------


def _scheme_app(*, trust: bool) -> TestClient:
    """A minimal app that reports the scheme it believes it is serving."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    from vexpath_api.observability import ForwardedSchemeMiddleware

    async def scheme(request: Request) -> PlainTextResponse:
        # url_for is what the templates use, so assert on the same thing.
        return PlainTextResponse(request.url_for("scheme").scheme)

    app = Starlette(routes=[Route("/scheme", scheme, name="scheme")])
    app.add_middleware(ForwardedSchemeMiddleware, trust_proxy_headers=trust)
    return TestClient(app)


def test_a_trusted_proxy_decides_the_scheme() -> None:
    """The bug this exists to prevent made the whole site unstyled.

    Fly terminates TLS, so the connection the application sees is plain
    http. Every page then emitted its stylesheet as an http URL while being
    served over https; browsers refuse that as mixed content and the site's
    own CSP refused it too, since ``style-src 'self'`` does not match
    another scheme. The page answered 200, the stylesheet answered 200 to
    anything asking directly, and only a browser console knew.
    """
    with _scheme_app(trust=True) as client:
        response = client.get("/scheme", headers={"X-Forwarded-Proto": "https"})
    assert response.text == "https"


def test_an_untrusted_proxy_header_is_ignored() -> None:
    # Off by default: a caller who can reach the application directly would
    # otherwise choose the scheme its own links are built with.
    with _scheme_app(trust=False) as client:
        response = client.get("/scheme", headers={"X-Forwarded-Proto": "https"})
    assert response.text == "http"


def test_only_a_real_scheme_is_believed() -> None:
    # A trusted proxy sends http or https. Anything else is somebody playing
    # games, and the scheme stays as the connection found it.
    with _scheme_app(trust=True) as client:
        response = client.get("/scheme", headers={"X-Forwarded-Proto": "javascript"})
    assert response.text == "http"


def test_the_first_hop_wins_through_a_chain_of_proxies() -> None:
    # X-Forwarded-Proto accumulates left to right, oldest first, so the
    # client's own scheme is the first entry.
    with _scheme_app(trust=True) as client:
        response = client.get("/scheme", headers={"X-Forwarded-Proto": "https, http"})
    assert response.text == "https"
