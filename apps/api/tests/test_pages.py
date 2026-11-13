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


def test_the_home_page_shows_output_before_it_explains_itself() -> None:
    """A visitor sees what the tool says before reading how it works.

    The page was six headings of argument -- "most of your alerts cannot hurt
    you", then Inventory, Match, Reach, Prove -- and no example of the thing
    anywhere. Somebody arriving had nothing to look at and nowhere to go.
    """
    settings = Settings(
        env=Environment.PRODUCTION,
        secret_key="a-real-secret-for-this-test",
        base_url="https://example.test",
        database_url="postgresql+psycopg://nobody@127.0.0.1:1/none",
    )
    app = create_app(settings)
    template = (TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")

    # Real output, including the line that distinguishes "no path exists"
    # from "nobody looked".
    assert "reachable_confirmed" in template
    assert "present and was" in template
    assert "traversed" in template

    # And it comes first.
    assert template.index("What it actually says") < template.index("How a verdict is reached")

    # The search form has somewhere to go.
    assert any(
        route.matches({"type": "http", "method": "GET", "path": "/packages", "headers": []})[
            0
        ].value
        >= 2
        for route in app.router.routes
    )


def test_a_layout_class_does_not_strip_a_panel_s_padding() -> None:
    """``.narrow`` and ``.panel`` are composed, so they must not collide.

    ``.narrow`` set ``padding: 0 1rem`` and sits after ``.panel`` in the
    stylesheet, so it won the cascade on every ``class="panel narrow"``:
    those panels had no vertical padding and their text sat flush against
    the border. Two classes that are always used together must divide the
    work -- one says how wide, the other how padded -- and a rule that
    quietly takes over the other's property is how a page ends up looking
    broken with nothing in it being wrong on its own.
    """
    import re

    css = (STATIC_DIR / "app.css").read_text(encoding="utf-8")
    block = re.search(r"\.narrow \{(.*?)\n\}", css, re.S)
    assert block is not None, ".narrow is gone; this test needs rewriting"

    declarations = [
        line.split("/*")[0].strip()
        for line in block.group(1).splitlines()
        if ":" in line.split("/*")[0]
    ]
    for declaration in declarations:
        property_name = declaration.split(":", 1)[0].strip()
        assert property_name not in {"padding", "padding-block", "margin", "margin-block"}, (
            f".narrow sets {property_name}, which overrides .panel because it comes "
            f"later in the stylesheet. Keep .narrow to width and centring."
        )


def test_the_home_page_survives_a_database_outage() -> None:
    """A landing page must not depend on a number printed on it.

    It did. Counting the corpus for the home page took a connection as a
    dependency, so the front page answered 500 while /healthz answered 200 --
    and this suite only passed because the developer's Postgres happened to
    be running. CI, with no database, found it on the next push.

    The count is decorative; the page is not. A failure costs one sentence.
    """
    settings = Settings(
        env=Environment.TEST,
        # Points at nothing, which is the whole point of the test.
        database_url="postgresql+psycopg://nobody@127.0.0.1:1/none",
    )
    with TestClient(create_app(settings)) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Most of your dependency alerts cannot hurt you" in response.text
    # The search still works -- it is a link, not a query.
    assert 'action="/packages"' in response.text
