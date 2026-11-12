"""The server-rendered HTML pages (ADR-0011)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from vexpath_api.main import create_app
from vexpath_api.templating import STATIC_DIR, TEMPLATES_DIR
from vexpath_platform.settings import Environment, Settings


@pytest.fixture
def client(clean_environment: None) -> Iterator[TestClient]:
    settings = Settings(env=Environment.TEST)
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def test_the_home_page_renders_server_side(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    # The content is in the first response, with no client-side fetch, which is
    # the whole point of rendering on the server.
    assert "<h1>" in body
    assert "dependency alerts" in body


def test_the_home_page_states_which_ecosystems_are_covered(client: TestClient) -> None:
    body = client.get("/").text
    assert "PyPI" in body
    # Saying "not checked" rather than implying "safe" is a product promise, so
    # the wording is asserted.
    assert "under investigation" in body


def test_no_javascript_is_served(client: TestClient) -> None:
    # ADR-0011: no JavaScript is authored in this repository. At this milestone
    # nothing is vendored either, so the page must reference no script at all.
    body = client.get("/").text
    assert "<script" not in body.lower()
    assert not list(STATIC_DIR.glob("*.js"))


def test_the_stylesheet_is_served(client: TestClient) -> None:
    response = client.get("/static/app.css")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")


def test_every_template_sets_a_title() -> None:
    # A page without a title is a page nobody can find in their browser history.
    for template in TEMPLATES_DIR.glob("*.html"):
        text = template.read_text(encoding="utf-8")
        assert "block title" in text, template.name


def test_autoescaping_is_on(client: TestClient) -> None:
    # Component names, licences and advisory text all come from outside this
    # system. Autoescaping is the backstop.
    templates = client.app.state.templates  # type: ignore[attr-defined]
    assert templates.env.autoescape is True
    rendered = templates.env.from_string("{{ value }}").render(value="<script>alert(1)</script>")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


# --- No link may point at a route that does not exist ---------------------


def test_every_internal_link_in_a_template_resolves() -> None:
    """Two links in the navigation answered 404 for weeks.

    They pointed at ``/docs``, which production deliberately disables, so the
    home page's "Read the API" button and the "API" item both returned
    ``{"detail":"Not Found"}``. Nothing failed: the pages rendered, the
    post-deploy checks passed, and the only report that reaches anyone is a
    user asking what is wrong with the site.

    Checked against a production application, because that is the one where a
    route can be absent.
    """
    import re

    settings = Settings(
        env=Environment.PRODUCTION,
        secret_key="a-real-secret-for-this-test",
        base_url="https://example.test",
        database_url="postgresql+psycopg://nobody@127.0.0.1:1/none",
    )
    app = create_app(settings)

    broken: list[str] = []
    for template in sorted(TEMPLATES_DIR.rglob("*.html")):
        for href in re.findall(r'href="(/[^"#]*)"', template.read_text(encoding="utf-8")):
            # Anything Jinja fills in at render time is not a literal link and
            # cannot be resolved from the source.
            if "{{" in href or "{%" in href:
                continue
            scope = {"type": "http", "method": "GET", "path": href, "headers": []}
            if not any(route.matches(scope)[0].value >= 2 for route in app.router.routes):
                broken.append(f"{template.name}: {href}")

    assert not broken, "templates link to routes this application does not serve: " + ", ".join(
        broken
    )
