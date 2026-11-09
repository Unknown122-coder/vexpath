"""Liveness, readiness and the security headers."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from sscp_api.main import SECURITY_HEADERS, create_app
from sscp_core import RESULTS_SCHEMA
from sscp_platform.settings import Environment, Settings


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
