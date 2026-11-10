"""The milestone's acceptance criteria, driven through a real browser.

Everything else in this suite asserts what a handler returns. These assert
what a browser can do with it, which is a different claim: a page can return
perfect HTML and still be unusable because a form posts to the wrong place or
a link points at a route that no longer exists.

The criteria, in order:

1. sign in, create a project, upload a scan with the key from the dashboard,
   view the finding's call path, publish it, and see the badge change;
2. **every action also works with JavaScript disabled** — not as a fallback,
   because there is no script to fall back from, and this is the test that
   keeps it that way;
3. the public report and package pages carry their content in the first
   response, with no client-side fetching.

The second is the one that would rot without a test. A single HTMX attribute
added without a form around it would pass every other test in the repository
and break the interface for a text browser, a screen reader, and anybody whose
script blocker is on.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import pytest
from sqlalchemy import insert, select, text

from vexpath_core.ids import new_ulid
from vexpath_db.engine import create_sync_engine
from vexpath_db.tables import api_keys, orgs
from vexpath_platform import apikeys

from .conftest import ORG_SLUG, Server, results_document, sign_in

#: Both markers. ``e2e`` is deselected by default (see the addopts in
#: pyproject.toml) because this suite cannot share a process with the
#: asynchronous database tests: Playwright needs the proactor event loop
#: and psycopg needs the selector one, and the policy is process-wide.
pytestmark = [pytest.mark.integration, pytest.mark.e2e]


# --- 1. The whole path somebody actually takes -----------------------------


def test_sign_in_create_a_project_upload_a_scan_and_publish_it(page: Any, server: Server) -> None:
    """The acceptance criterion, as one journey.

    Each piece is covered on its own elsewhere; what this asserts is that they
    join up, which is the part that silently fails when two halves are built a
    week apart.
    """
    sign_in(page)
    assert "Acceptance Ltd" in page.content()

    # Create a project.
    page.fill("#slug", "web")
    page.get_by_role("button", name="Create project", exact=True).click()
    page.wait_for_url("**/app")
    assert "web" in page.content()

    # Issue a key, and read it off the page exactly as a person would.
    page.goto("/app/keys")
    page.fill("#name", "acceptance")
    page.get_by_role("button", name="Create key", exact=True).click()
    secret = page.get_attribute("#new-secret", "value")
    assert secret.startswith("vexpath_live_")

    # Upload a scan with that key, over HTTP, as the command line would.
    uploaded = httpx.post(
        f"{server.base_url}/v1/scans",
        json={"project": "web", "results": results_document()},
        headers={"Authorization": f"Bearer {secret}"},
        timeout=30,
    )
    assert uploaded.status_code == 201, uploaded.text

    # The scan is on the dashboard.
    page.goto("/app")
    assert "web" in page.content()

    # Open the finding and read its call path.
    page.goto(f"/app/scans/{uploaded.json()['id']}")
    page.get_by_role("link", name="CVE-2026-0001", exact=True).click()
    content = page.content()
    assert "The call path" in content
    assert "app.main:handler" in content
    assert "jinja2/sandbox.py:402" in content

    # Publish, and check the public report and the badge.
    page.goto("/app")
    page.get_by_role("button", name="Publish", exact=True).click()
    page.wait_for_url("**/app")

    page.goto(f"/p/{ORG_SLUG}/web")
    assert "CVE-2026-0001" in page.content()

    badge = httpx.get(f"{server.base_url}/badge/{ORG_SLUG}/web.svg", timeout=30)
    assert badge.status_code == 200
    # The badge reflects the scan, not a cached default. The criterion allows
    # five minutes; it is immediate because the badge reads the scan rather
    # than a materialised counter.
    assert "1 reachable" in badge.text

    # Unpublishing withdraws both.
    page.goto("/app")
    page.get_by_role("button", name="Unpublish", exact=True).click()
    page.wait_for_url("**/app")
    assert page.goto(f"/p/{ORG_SLUG}/web").status == 404


# --- 2. The same thing with JavaScript disabled ----------------------------


def test_signing_in_works_with_javascript_disabled(scripted_out: Any) -> None:
    sign_in(scripted_out)
    # An authorisation code exchange is a sequence of redirects, which is the
    # one thing the web has always done without help.
    assert "Acceptance Ltd" in scripted_out.content()


def test_creating_a_project_works_with_javascript_disabled(scripted_out: Any) -> None:
    sign_in(scripted_out)
    scripted_out.fill("#slug", "no-script")
    scripted_out.get_by_role("button", name="Create project", exact=True).click()
    scripted_out.wait_for_url("**/app")
    # A plain form POST answered with a redirect. Not a fallback: there is no
    # script to fall back from.
    assert "no-script" in scripted_out.content()


def test_issuing_a_key_works_with_javascript_disabled(scripted_out: Any) -> None:
    sign_in(scripted_out)
    scripted_out.goto("/app/keys")
    scripted_out.fill("#name", "ci")
    scripted_out.get_by_role("button", name="Create key", exact=True).click()
    secret = scripted_out.get_attribute("#new-secret", "value")
    # Shown in the response to the POST rather than copied by script, which is
    # why it is readable here at all.
    assert secret.startswith("vexpath_live_")


def test_publishing_works_with_javascript_disabled(scripted_out: Any) -> None:
    sign_in(scripted_out)
    # Named to collide with the button's label on purpose: addressing controls
    # by text rather than by role matched this project's name instead of the
    # button, and the failure looked like publishing being broken.
    scripted_out.fill("#slug", "published")
    scripted_out.get_by_role("button", name="Create project", exact=True).click()
    scripted_out.wait_for_url("**/app")
    scripted_out.get_by_role("button", name="Publish", exact=True).click()
    scripted_out.wait_for_url("**/app")
    assert "Unpublish" in scripted_out.content()


def test_registering_a_webhook_works_with_javascript_disabled(scripted_out: Any) -> None:
    sign_in(scripted_out)
    scripted_out.goto("/app/webhooks")
    scripted_out.fill("#url", "https://hooks.example.com/x")
    scripted_out.check("input[value='scan.completed']")
    scripted_out.get_by_role("button", name="Add webhook", exact=True).click()
    assert "whsec_" in scripted_out.get_attribute("#new-secret", "value")


def test_the_policy_editor_works_with_javascript_disabled(scripted_out: Any) -> None:
    sign_in(scripted_out)
    scripted_out.fill("#slug", "gated")
    scripted_out.get_by_role("button", name="Create project", exact=True).click()
    scripted_out.wait_for_url("**/app")

    scripted_out.goto("/app/projects/gated/policy")
    scripted_out.fill("#expression", "findings.exists(f, f.kev)")
    scripted_out.get_by_role("button", name="Save", exact=True).click()
    # Two submit buttons in one form, distinguished by their value. A control
    # that needed script to choose between them would not work here.
    assert "Saved" in scripted_out.content()


def test_signing_out_works_with_javascript_disabled(scripted_out: Any) -> None:
    sign_in(scripted_out)
    scripted_out.get_by_role("button", name="Sign out acceptance", exact=True).click()
    scripted_out.wait_for_url("**/")
    # A POST, because a sign-out on a GET can be triggered by any image tag on
    # any page -- and it still works without script.
    assert "Sign in" in scripted_out.content()


def test_no_page_in_the_interface_loads_a_script(page: Any) -> None:
    sign_in(page)
    page.fill("#slug", "audited")
    page.get_by_role("button", name="Create project", exact=True).click()
    page.wait_for_url("**/app")

    for path in (
        "/",
        "/login",
        "/app",
        "/app/keys",
        "/app/webhooks",
        "/app/projects/audited",
        "/app/projects/audited/policy",
    ):
        page.goto(path)
        content = page.content()
        # Asserted by inspecting the markup rather than by trusting the
        # templates: one added attribute is all it takes.
        assert "<script" not in content.lower(), path
        assert "onclick" not in content.lower(), path
        assert "onsubmit" not in content.lower(), path


# --- 3. The public pages carry their content -------------------------------


def test_the_public_report_is_complete_in_the_first_response(page: Any, server: Server) -> None:
    sign_in(page)
    page.fill("#slug", "reported")
    page.get_by_role("button", name="Create project", exact=True).click()
    page.wait_for_url("**/app")
    page.goto("/app/keys")
    page.fill("#name", "ci")
    page.get_by_role("button", name="Create key", exact=True).click()
    secret = page.get_attribute("#new-secret", "value")

    httpx.post(
        f"{server.base_url}/v1/scans",
        json={"project": "reported", "results": results_document()},
        headers={"Authorization": f"Bearer {secret}"},
        timeout=30,
    )
    page.goto("/app")
    page.get_by_role("button", name="Publish", exact=True).click()
    page.wait_for_url("**/app")

    # Fetched without a browser at all: if the content needs script, this is
    # empty, and the entire reason to publish a report is that other people
    # and other machines can read it.
    raw = httpx.get(f"{server.base_url}/p/{ORG_SLUG}/reported", timeout=30)
    assert raw.status_code == 200
    assert "CVE-2026-0001" in raw.text
    assert "<script" not in raw.text.lower()


def test_the_public_report_makes_no_requests_after_the_first(page: Any, server: Server) -> None:
    sign_in(page)
    page.fill("#slug", "watched")
    page.get_by_role("button", name="Create project", exact=True).click()
    page.wait_for_url("**/app")
    page.get_by_role("button", name="Publish", exact=True).click()
    page.wait_for_url("**/app")

    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url))
    page.goto(f"/p/{ORG_SLUG}/watched")

    # The document and its stylesheet, and nothing else. No fetch, no XHR, no
    # deferred list: a report whose content arrives in a second request cannot
    # be read by a crawler or by anybody whose second request did not make it.
    fetched = [url for url in requests if not url.endswith((".css", ".ico", ".svg"))]
    assert len(fetched) == 1, fetched


def test_the_package_page_needs_no_account(page: Any, server: Server) -> None:
    raw = httpx.get(f"{server.base_url}/package/PyPI/requests", timeout=30)
    assert raw.status_code == 200
    # Built entirely from the global advisory corpus, which is what lets it
    # exist with no organisation in scope and be useful to somebody who has
    # never uploaded anything.
    assert "requests" in raw.text
    assert "<script" not in raw.text.lower()


def test_the_badge_references_nothing_external(page: Any, server: Server) -> None:
    sign_in(page)
    page.fill("#slug", "badged")
    page.get_by_role("button", name="Create project", exact=True).click()
    page.wait_for_url("**/app")
    page.get_by_role("button", name="Publish", exact=True).click()
    page.wait_for_url("**/app")

    badge = httpx.get(f"{server.base_url}/badge/{ORG_SLUG}/badged.svg", timeout=30)
    assert badge.status_code == 200
    # A badge that fetched anything would report every view of every README
    # that embeds it back to wherever it fetched from.
    for marker in ("<image", "<use", "@import", "<script", "xlink:href"):
        assert marker not in badge.text.lower(), marker

    # The only URL in the document is the SVG namespace, which is an
    # identifier rather than something a renderer retrieves.
    urls = re.findall(r"https?://[^\"'\s>]+", badge.text)
    assert urls == ["http://www.w3.org/2000/svg"], urls


# --- A private project stays private ---------------------------------------


def test_a_private_project_has_no_public_page_or_badge(page: Any, server: Server) -> None:
    sign_in(page)
    page.fill("#slug", "secret-service")
    page.get_by_role("button", name="Create project", exact=True).click()
    page.wait_for_url("**/app")

    assert (
        httpx.get(f"{server.base_url}/p/{ORG_SLUG}/secret-service", timeout=30).status_code == 404
    )
    assert (
        httpx.get(f"{server.base_url}/badge/{ORG_SLUG}/secret-service.svg", timeout=30).status_code
        == 404
    )


def test_a_project_that_does_not_exist_answers_identically(page: Any, server: Server) -> None:
    sign_in(page)
    page.fill("#slug", "secret-service")
    page.get_by_role("button", name="Create project", exact=True).click()
    page.wait_for_url("**/app")

    private = httpx.get(f"{server.base_url}/p/{ORG_SLUG}/secret-service", timeout=30)
    absent = httpx.get(f"{server.base_url}/p/{ORG_SLUG}/no-such-thing", timeout=30)
    # Identical, so nobody can enumerate private project names.
    assert private.status_code == absent.status_code == 404
    assert private.json() == absent.json()


def test_the_dashboard_needs_a_session(scripted_out: Any) -> None:
    scripted_out.goto("/app")
    # Redirected to sign in rather than refused with JSON: a 401 body is the
    # right answer to a mis-authenticated API call and a dead end for a person.
    assert "/login" in scripted_out.url
    assert "Sign in" in scripted_out.content()


def test_an_api_key_cannot_be_used_as_a_browser_credential(
    page: Any, server: Server, integration_database_url: str
) -> None:
    engine = create_sync_engine(integration_database_url)
    try:
        with engine.begin() as connection:
            org_id = connection.execute(
                select(orgs.c.id).where(orgs.c.slug == ORG_SLUG)
            ).scalar_one_or_none()
            if org_id is None:
                sign_in(page)
                org_id = connection.execute(
                    select(orgs.c.id).where(orgs.c.slug == ORG_SLUG)
                ).scalar_one()
            connection.execute(
                text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id}
            )
            issued = apikeys.issue()
            connection.execute(
                insert(api_keys).values(
                    id=new_ulid(),
                    org_id=org_id,
                    name="probe",
                    key_hash=issued.key_hash,
                    prefix=issued.prefix,
                )
            )
    finally:
        engine.dispose()

    response = httpx.get(
        f"{server.base_url}/app",
        headers={"Authorization": f"Bearer {issued.secret}"},
        follow_redirects=False,
        timeout=30,
    )
    # No endpoint accepts both credentials, which is what keeps /v1 out of
    # reach of a cross-site form carrying an ambient cookie.
    assert response.status_code == 303
    assert "/login" in response.headers["location"]
