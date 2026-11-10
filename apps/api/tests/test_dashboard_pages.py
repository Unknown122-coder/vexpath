"""The webhooks screen and the scan diff.

Two pages, and what is tested about each is the thing it exists for.

The webhooks screen exists so the *refusals* reach a person. A URL field that
answers "not allowed" sends somebody to a support channel; one that says which
rule and why is the difference between a security control and an obstacle. So
the test asserts the explanation, not only the status code.

The diff exists because the question after a build is "what did my change do",
not "what is wrong with this project". The assertion that matters is that a
finding whose verdict moved appears in its own section: in a diff of
identities alone, not-reachable becoming reachable would not show up at all,
and that is the most important line the page can carry.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, insert, select, text

from vexpath_api.main import create_app
from vexpath_api.oauth import Identity, OAuthError
from vexpath_core.ids import new_ulid
from vexpath_db.engine import create_app_engine, create_sync_engine
from vexpath_db.tables import (
    components,
    findings,
    orgs,
    projects,
    reachability_results,
    sboms,
    scans,
    webhooks,
)
from vexpath_platform.settings import Environment, Settings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

OWNER = Identity(subject="9501", login="pages", name="Pages Inc", email=None)
SLUG = "pages"
SECRET_KEY = "a-process-secret-for-the-page-tests"


@dataclass
class FakeProvider:
    identities: dict[str, Identity] = field(default_factory=lambda: {"code": OWNER})

    @property
    def provider(self) -> str:
        return "github"

    def authorize_url(self, *, redirect_uri: str, state: str) -> str:
        del redirect_uri
        return f"https://github.test/authorize?state={state}"

    async def identity(self, *, code: str, redirect_uri: str) -> Identity:
        del redirect_uri
        if code not in self.identities:
            msg = "unknown code"
            raise OAuthError(msg)
        return self.identities[code]


@pytest.fixture
def database(integration_database_url: str) -> Iterator[Engine]:
    engine = create_sync_engine(integration_database_url, connect_timeout=3)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1 FROM webhooks LIMIT 1"))
    except Exception as exc:  # noqa: BLE001 - a missing database skips, not fails
        engine.dispose()
        pytest.skip(f"integration database unavailable: {type(exc).__name__}: {exc}")
    _wipe(engine)
    yield engine
    _wipe(engine)
    engine.dispose()


def _wipe(engine: Engine) -> None:
    with engine.begin() as connection:
        for row in connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).all():
            connection.execute(
                text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": row.id}
            )
            connection.execute(delete(orgs).where(orgs.c.id == row.id))


@pytest.fixture
def client(integration_database_url: str, database: Engine) -> Iterator[TestClient]:
    settings = Settings(
        env=Environment.TEST, database_url=integration_database_url, secret_key=SECRET_KEY
    )
    engine = create_app_engine(integration_database_url)
    try:
        app = create_app(settings, engine=engine, identity_provider=FakeProvider())
        with TestClient(app, follow_redirects=False) as test_client:
            start = test_client.get("/auth/github/start")
            state = re.search(r"state=([^&]+)", start.headers["location"])
            assert state is not None
            assert (
                test_client.get(
                    "/auth/github/callback", params={"code": "code", "state": state.group(1)}
                ).status_code
                == 303
            )
            yield test_client
    finally:
        asyncio.run(engine.dispose())


def csrf_of(client: TestClient, path: str) -> str:
    page = client.get(path)
    assert page.status_code == 200, page.text
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None, "no CSRF token in the rendered form"
    return match.group(1)


def org_of(database: Engine) -> str:
    with database.connect() as connection:
        value: str = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        return value


# --- The webhooks screen ----------------------------------------------------


def test_the_page_states_the_rules_before_they_are_broken(client: TestClient) -> None:
    page = client.get("/app/webhooks")
    assert page.status_code == 200
    # Somebody who understands why will not spend ten minutes trying
    # variations of a private address.
    assert "public internet" in page.text
    assert "metadata" in page.text
    assert "Redirects are not followed" in page.text
    assert "<script" not in page.text.lower()


def test_a_webhook_can_be_added_and_its_secret_is_shown_once(
    client: TestClient, database: Engine
) -> None:
    response = client.post(
        "/app/webhooks",
        data={
            "csrf_token": csrf_of(client, "/app/webhooks"),
            "url": "https://hooks.example.com/x",
            "events": ["scan.completed"],
        },
    )
    assert response.status_code == 201, response.text
    match = re.search(r'value="(whsec_[A-Za-z0-9_-]+)"', response.text)
    assert match is not None, "the signing secret was not shown"
    secret = match.group(1)
    assert "never displayed again" in response.text

    later = client.get("/app/webhooks")
    # True rather than a policy: only the ciphertext is stored, and the page
    # has no way to decrypt and display it.
    assert secret not in later.text


def test_the_page_tells_a_receiver_how_to_verify(client: TestClient) -> None:
    response = client.post(
        "/app/webhooks",
        data={
            "csrf_token": csrf_of(client, "/app/webhooks"),
            "url": "https://hooks.example.com/x",
            "events": ["ping"],
        },
    )
    # The instruction is on the one page that has the secret, because that is
    # the moment somebody is writing the receiver.
    assert "HMAC-SHA256" in response.text
    assert "constant time" in response.text
    assert "X-Vexpath-Timestamp" in response.text


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://hooks.example.com/x", "https"),
        ("https://169.254.169.254/x", "metadata"),
        ("https://127.0.0.1/x", "public"),
        ("https://hooks.example.com:9200/x", "port"),
        ("https://user:pw@hooks.example.com/x", "credentials"),
    ],
)
def test_a_refused_url_says_which_rule_and_why(
    client: TestClient, database: Engine, url: str, expected: str
) -> None:
    response = client.post(
        "/app/webhooks",
        data={"csrf_token": csrf_of(client, "/app/webhooks"), "url": url, "events": ["ping"]},
    )
    assert response.status_code == 422
    assert expected in response.text
    # What was typed comes back, so the fix is one edit rather than a retype.
    assert url in response.text

    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_of(database)}
        )
        assert connection.execute(select(webhooks)).mappings().all() == []


def test_a_webhook_with_no_events_is_refused(client: TestClient) -> None:
    response = client.post(
        "/app/webhooks",
        data={"csrf_token": csrf_of(client, "/app/webhooks"), "url": "https://a.example.com/x"},
    )
    assert response.status_code == 422
    # A subscription to nothing looks like a working subscription.
    assert "subscribed to nothing is silence" in response.text


def test_an_unknown_project_is_refused(client: TestClient) -> None:
    response = client.post(
        "/app/webhooks",
        data={
            "csrf_token": csrf_of(client, "/app/webhooks"),
            "url": "https://a.example.com/x",
            "events": ["ping"],
            "project": "nope",
        },
    )
    assert response.status_code == 422
    assert "no project called nope" in response.text


def test_adding_a_webhook_needs_the_csrf_token(client: TestClient, database: Engine) -> None:
    client.post("/app/webhooks", data={"url": "https://a.example.com/x", "events": ["ping"]})
    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_of(database)}
        )
        assert connection.execute(select(webhooks)).mappings().all() == []


def test_a_disabled_webhook_says_so_and_can_be_re_enabled(
    client: TestClient, database: Engine
) -> None:
    client.post(
        "/app/webhooks",
        data={
            "csrf_token": csrf_of(client, "/app/webhooks"),
            "url": "https://hooks.example.com/x",
            "events": ["ping"],
        },
    )
    org_id = org_of(database)
    with database.begin() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        webhook_id = connection.execute(select(webhooks.c.id)).scalar_one()
        connection.execute(
            webhooks.update()
            .where(webhooks.c.id == webhook_id)
            .values(disabled_at=text("now()"), failure_count=25)
        )

    page = client.get("/app/webhooks")
    # Kept rather than deleted so somebody can see that it stopped and why.
    assert "disabled" in page.text
    assert "repeated failures" in page.text

    client.post(
        f"/app/webhooks/{webhook_id}/enable",
        data={"csrf_token": csrf_of(client, "/app/webhooks")},
    )
    with database.connect() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        row = connection.execute(select(webhooks)).mappings().one()
    assert row["disabled_at"] is None
    # Cleared, or the next delivery's first retry disables it again.
    assert row["failure_count"] == 0


def test_a_webhook_can_be_deleted(client: TestClient, database: Engine) -> None:
    client.post(
        "/app/webhooks",
        data={
            "csrf_token": csrf_of(client, "/app/webhooks"),
            "url": "https://hooks.example.com/x",
            "events": ["ping"],
        },
    )
    org_id = org_of(database)
    with database.connect() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        webhook_id = connection.execute(select(webhooks.c.id)).scalar_one()

    response = client.post(
        f"/app/webhooks/{webhook_id}/delete",
        data={"csrf_token": csrf_of(client, "/app/webhooks")},
    )
    assert response.status_code == 303
    with database.connect() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        assert connection.execute(select(webhooks)).mappings().all() == []


def test_the_webhooks_page_is_behind_the_session(client: TestClient) -> None:
    client.cookies.clear()
    response = client.get("/app/webhooks")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


# --- The scan diff ----------------------------------------------------------


@dataclass
class Scans:
    project_id: str
    first: str
    second: str


def _seed_scan(
    connection: Any,
    *,
    org_id: str,
    project_id: str,
    minutes_ago: int,
    findings_spec: list[dict[str, Any]],
) -> str:
    scan_id = new_ulid()
    connection.execute(
        insert(scans).values(
            id=scan_id,
            org_id=org_id,
            project_id=project_id,
            core_version="0.0.1",
            status="completed",
            summary={},
            created_at=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        )
    )
    sbom_id = new_ulid()
    connection.execute(
        insert(sboms).values(
            id=sbom_id,
            org_id=org_id,
            scan_id=scan_id,
            format="cyclonedx-1.6-json",
            document_hash="a" * 64,
            component_count=len(findings_spec),
        )
    )
    for spec in findings_spec:
        component_id = new_ulid()
        connection.execute(
            insert(components).values(
                id=component_id,
                org_id=org_id,
                sbom_id=sbom_id,
                purl=spec["purl"],
                ecosystem="PyPI",
                name=spec["name"],
                version=spec["version"],
                direct=True,
                scope="runtime",
                licenses=[],
                hashes={},
            )
        )
        finding_id = new_ulid()
        connection.execute(
            insert(findings).values(
                id=finding_id,
                org_id=org_id,
                scan_id=scan_id,
                component_id=component_id,
                advisory_id=spec["advisory"],
                severity=spec.get("severity", "HIGH"),
                verdict=spec["verdict"],
                notes=[],
            )
        )
        if spec.get("reach"):
            connection.execute(
                insert(reachability_results).values(
                    id=new_ulid(),
                    org_id=org_id,
                    finding_id=finding_id,
                    status=spec["reach"],
                    confidence="high",
                    matched_symbols=["x.y"] if "reachable" in spec["reach"] else [],
                    searched_symbols=["x.y"],
                    shortest_path=[],
                    path_count=0,
                    via_dynamic_edges=False,
                    explanation="",
                )
            )
    return scan_id


@pytest.fixture
def two_scans(client: TestClient, database: Engine) -> Scans:
    """Two scans whose difference covers every case the page has to show."""
    org_id = org_of(database)
    with database.begin() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        project_id = new_ulid()
        connection.execute(
            insert(projects).values(
                id=project_id,
                org_id=org_id,
                slug="svc",
                visibility="private",
                entry_points=[],
                settings={},
            )
        )
        first = _seed_scan(
            connection,
            org_id=org_id,
            project_id=project_id,
            minutes_ago=60,
            findings_spec=[
                # Stays identical.
                {
                    "advisory": "CVE-2026-1111",
                    "purl": "pkg:pypi/stable@1.0.0",
                    "name": "stable",
                    "version": "1.0.0",
                    "verdict": "affected",
                    "reach": "reachable_confirmed",
                },
                # Changes verdict in the second scan.
                {
                    "advisory": "CVE-2026-2222",
                    "purl": "pkg:pypi/moved@2.0.0",
                    "name": "moved",
                    "version": "2.0.0",
                    "verdict": "not_affected",
                    "reach": "unreachable",
                },
                # Gone in the second scan.
                {
                    "advisory": "CVE-2026-3333",
                    "purl": "pkg:pypi/removed@3.0.0",
                    "name": "removed",
                    "version": "3.0.0",
                    "verdict": "affected",
                    "reach": "reachable_confirmed",
                },
            ],
        )
        second = _seed_scan(
            connection,
            org_id=org_id,
            project_id=project_id,
            minutes_ago=5,
            findings_spec=[
                {
                    "advisory": "CVE-2026-1111",
                    "purl": "pkg:pypi/stable@1.0.0",
                    "name": "stable",
                    "version": "1.0.0",
                    "verdict": "affected",
                    "reach": "reachable_confirmed",
                },
                {
                    "advisory": "CVE-2026-2222",
                    "purl": "pkg:pypi/moved@2.0.0",
                    "name": "moved",
                    "version": "2.0.0",
                    # The line that matters: it became reachable.
                    "verdict": "affected",
                    "reach": "reachable_confirmed",
                },
                {
                    "advisory": "CVE-2026-4444",
                    "purl": "pkg:pypi/arrived@4.0.0",
                    "name": "arrived",
                    "version": "4.0.0",
                    "verdict": "affected",
                    "reach": "reachable_confirmed",
                },
            ],
        )
    return Scans(project_id=project_id, first=first, second=second)


def test_the_diff_separates_appeared_changed_and_gone(client: TestClient, two_scans: Scans) -> None:
    page = client.get(f"/app/scans/{two_scans.second}/diff")
    assert page.status_code == 200
    assert "CVE-2026-4444" in page.text  # appeared
    assert "CVE-2026-3333" in page.text  # gone
    assert "CVE-2026-2222" in page.text  # changed
    # The one that did not move is a count, not a row: the page is about the
    # change, and a list of everything buries it.
    assert "1 finding unchanged" in page.text


def test_a_verdict_that_moved_has_its_own_section_with_both_values(
    client: TestClient, two_scans: Scans
) -> None:
    page = client.get(f"/app/scans/{two_scans.second}/diff")
    changed = page.text[page.text.index("Changed verdict") : page.text.index("Gone")]
    # In a diff of identities alone, not-reachable becoming reachable would
    # not appear at all -- and it is the most important line here.
    assert "CVE-2026-2222" in changed
    assert "unreachable" in changed
    assert "reachable_confirmed" in changed


def test_the_sections_are_ordered_so_what_appeared_is_read_first(
    client: TestClient, two_scans: Scans
) -> None:
    page = client.get(f"/app/scans/{two_scans.second}/diff")
    assert page.text.index("Appeared") < page.text.index("Changed verdict")
    assert page.text.index("Changed verdict") < page.text.index("Gone")


def test_a_first_scan_says_there_is_nothing_to_compare_against(
    client: TestClient, two_scans: Scans
) -> None:
    page = client.get(f"/app/scans/{two_scans.first}/diff")
    assert page.status_code == 200
    # The ordinary state of a new project, and it must read as an explanation
    # rather than as an empty page.
    assert "Nothing to compare against" in page.text
    assert "first scan" in page.text


def test_the_scan_page_links_to_the_diff(client: TestClient, two_scans: Scans) -> None:
    page = client.get(f"/app/scans/{two_scans.second}")
    assert f"/app/scans/{two_scans.second}/diff" in page.text


def test_the_diff_of_another_organisation_s_scan_is_not_found(client: TestClient) -> None:
    assert client.get(f"/app/scans/{new_ulid()}/diff").status_code == 404


def test_the_diff_has_no_script(client: TestClient, two_scans: Scans) -> None:
    page = client.get(f"/app/scans/{two_scans.second}/diff")
    assert "<script" not in page.text.lower()
