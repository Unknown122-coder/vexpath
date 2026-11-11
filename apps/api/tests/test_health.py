"""Liveness, readiness and the security headers."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from vexpath_api.main import SECURITY_HEADERS, create_app
from vexpath_core import RESULTS_SCHEMA
from vexpath_platform.settings import Environment, Settings


@pytest.fixture
def client(clean_environment: None) -> Iterator[TestClient]:
    settings = Settings(
        env=Environment.TEST,
        # Points at nothing. Engine creation is lazy, so liveness still works
        # and readiness correctly reports the database as unavailable.
        database_url="postgresql+psycopg://nobody@127.0.0.1:1/none",
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def test_liveness_does_not_depend_on_the_database(client: TestClient) -> None:
    """A database outage must not make an orchestrator kill a healthy process."""
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["results_schema"] == RESULTS_SCHEMA


def test_liveness_publishes_what_this_build_can_analyse(client: TestClient) -> None:
    # A verdict means different things depending on which ecosystems the build
    # covers, so a client can read that off the health endpoint (ADR-0012).
    assert client.get("/healthz").json()["reachability_ecosystems"] == ["PyPI"]


def test_readiness_reports_an_unreachable_database(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["dependencies"][0]["name"] == "database"
    assert body["dependencies"][0]["ok"] is False


def test_security_headers_are_on_every_response(client: TestClient) -> None:
    response = client.get("/healthz")
    for header, value in SECURITY_HEADERS.items():
        assert response.headers[header] == value


def test_the_content_security_policy_forbids_inline_and_third_party_script() -> None:
    # The UI loads same-origin assets only, so no inline script or CDN can slip
    # in by accident (docs/06-threat-model.md).
    policy = SECURITY_HEADERS["Content-Security-Policy"]
    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy
    assert "frame-ancestors 'none'" in policy


def _client(base_url: str) -> TestClient:
    settings = Settings(
        env=Environment.TEST,
        database_url="postgresql+psycopg://nobody@127.0.0.1:1/none",
        base_url=base_url,
    )
    return TestClient(create_app(settings))


def test_a_deployment_served_over_https_pins_the_browser_to_it() -> None:
    """Without this, the first request of every session is interceptable.

    Fly redirects http to https, but a redirect happens *after* the request
    arrives: if that request carried a session cookie or an API key, it has
    already crossed the network in clear. The header is what stops the
    browser doing it a second time.
    """
    with _client("https://vexpath.fly.dev") as client:
        header = client.get("/healthz").headers["Strict-Transport-Security"]
    assert "max-age=31536000" in header
    assert "includeSubDomains" in header
    # Not claimed, because being on the preload list is a submission to a
    # list compiled into browsers and removal takes months.
    assert "preload" not in header


def test_local_development_is_not_pinned_to_https() -> None:
    """A browser told to pin ``localhost`` honours it for a year.

    And not just for this project: every other service on the machine's
    localhost goes with it, with no obvious way to undo it. So the header is
    tied to the scheme actually being served rather than sent always.
    """
    with _client("http://localhost:8000") as client:
        assert "Strict-Transport-Security" not in client.get("/healthz").headers


def test_readiness_answers_within_its_own_timeout(client: TestClient) -> None:
    """The probe must answer faster than the orchestrator asks again.

    It did not. libpq waits for a connection indefinitely unless told not to,
    and a request to an address nothing was listening on took 130 seconds to
    come back -- while holding a worker. Fly probes ``/readyz`` every fifteen
    seconds with a five-second timeout, so that is a growing pile of stuck
    requests on the one machine that is meant to be serving.

    The bound is checked here rather than trusted, because the symptom of
    losing it is a slow test suite, which reads as annoyance rather than as
    the defect it is.
    """
    import time

    started = time.monotonic()
    response = client.get("/readyz")
    elapsed = time.monotonic() - started

    assert response.status_code == 503
    assert response.json()["dependencies"][0]["ok"] is False
    assert elapsed < 8, f"the readiness probe took {elapsed:.0f}s to say no"
