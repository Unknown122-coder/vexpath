"""Signing in, the signed-in pages, and the loop that joins them to the CLI.

The identity provider is a stand-in, so every branch of the sign-in flow is
reachable without a network: a cancelled authorisation, a forged state
parameter, a provider that errors. Those are the branches that otherwise
answer 500 the first time a real person meets them.

Everything else runs against real HTTP and a real database, because what is
being tested is partly row-level security and partly the browser's own rules
about cookies, and neither survives being mocked.

The test that matters most is the one at the end: a key created on the keys
page authenticates the command-line tool. That is the whole product loop --
sign in, make a project, issue a key, upload -- and until it passes, each half
works and the thing does not.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, text

from vexpath_api.main import create_app
from vexpath_api.oauth import Identity, OAuthError
from vexpath_db.engine import create_app_engine, create_sync_engine
from vexpath_db.tables import api_keys, orgs, projects, sessions, users, users_orgs
from vexpath_platform import apikeys
from vexpath_platform import sessions as tokens
from vexpath_platform.settings import Environment, Settings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

#: Marks what these tests own, so running them does not disturb a database
#: somebody is using.
MARKER = "ZZLOGIN"

ALICE = Identity(subject="4001", login="alice", name="Alice Example", email="alice@example.com")
BOB = Identity(subject="4002", login="bob", name=None, email=None)


@dataclass
class FakeProvider:
    """An identity provider that answers from a dictionary.

    Codes map to identities; codes in ``failures`` raise. That is enough to
    reach every path in the callback, which is the point: the failure paths
    are the ones nobody exercises by hand.
    """

    identities: dict[str, Identity] = field(default_factory=dict)
    failures: set[str] = field(default_factory=set)
    authorize_calls: list[dict[str, str]] = field(default_factory=list)

    @property
    def provider(self) -> str:
        return "github"

    def authorize_url(self, *, redirect_uri: str, state: str) -> str:
        self.authorize_calls.append({"redirect_uri": redirect_uri, "state": state})
        return f"https://github.test/login/oauth/authorize?state={state}"

    async def identity(self, *, code: str, redirect_uri: str) -> Identity:
        del redirect_uri
        if code in self.failures:
            msg = "GitHub refused the authorisation code"
            raise OAuthError(msg)
        if code not in self.identities:
            msg = "unknown code"
            raise OAuthError(msg)
        return self.identities[code]


@pytest.fixture
def database(integration_database_url: str) -> Iterator[Engine]:
    engine = create_sync_engine(integration_database_url, connect_timeout=3)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1 FROM sessions LIMIT 1"))
    except Exception as exc:  # noqa: BLE001 - a missing database skips, not fails
        engine.dispose()
        pytest.skip(f"integration database unavailable: {type(exc).__name__}: {exc}")
    _wipe(engine)
    yield engine
    _wipe(engine)
    engine.dispose()


def _wipe(engine: Engine) -> None:
    """Remove every organisation these tests created.

    By slug prefix rather than by a known identifier, because sign-in invents
    the identifier and the slug is the only thing the test can predict.
    """
    with engine.begin() as connection:
        rows = connection.execute(
            select(orgs.c.id).where(
                orgs.c.slug.in_(["alice", "bob", "alice-1", f"{MARKER.lower()}-other"])
            )
        ).all()
        for row in rows:
            connection.execute(
                text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": row.id}
            )
            connection.execute(delete(orgs).where(orgs.c.id == row.id))


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider(identities={"alice-code": ALICE, "bob-code": BOB}, failures={"broken"})


@pytest.fixture
def client(
    integration_database_url: str, database: Engine, provider: FakeProvider
) -> Iterator[TestClient]:
    settings = Settings(env=Environment.TEST, database_url=integration_database_url)
    engine = create_app_engine(integration_database_url)
    try:
        app = create_app(settings, engine=engine, identity_provider=provider)
        with TestClient(app, follow_redirects=False) as test_client:
            yield test_client
    finally:
        asyncio.run(engine.dispose())


@pytest.fixture
def unconfigured(integration_database_url: str, database: Engine) -> Iterator[TestClient]:
    """An application with no identity provider, as a fresh deployment is."""
    settings = Settings(env=Environment.TEST, database_url=integration_database_url)
    engine = create_app_engine(integration_database_url)
    try:
        with TestClient(create_app(settings, engine=engine), follow_redirects=False) as test:
            yield test
    finally:
        asyncio.run(engine.dispose())


def sign_in(client: TestClient, code: str = "alice-code", *, next_path: str | None = None) -> str:
    """Drive the whole flow and return where it landed.

    Written as a helper because every test below starts here, and because
    driving it properly -- following the state parameter through the provider
    rather than minting a cookie -- is what makes these tests about the flow
    instead of about the fixture.
    """
    start = client.get("/auth/github/start", params={"next": next_path} if next_path else None)
    assert start.status_code == 303, start.text
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

    callback = client.get("/auth/github/callback", params={"code": code, "state": state})
    assert callback.status_code == 303, callback.text
    return callback.headers["location"]


def csrf_of(client: TestClient, path: str = "/app") -> str:
    """The CSRF token from a rendered page.

    Read out of the HTML rather than computed, so a template that stopped
    emitting it fails these tests rather than passing them.
    """
    page = client.get(path)
    assert page.status_code == 200, page.text
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None, "no CSRF token in the rendered form"
    return match.group(1)


# --- The sign-in page -------------------------------------------------------


def test_the_sign_in_page_offers_github(client: TestClient) -> None:
    page = client.get("/login")
    assert page.status_code == 200
    assert "/auth/github/start" in page.text
    # No password field, because there is no password column to put one in.
    assert 'type="password"' not in page.text


def test_an_unconfigured_deployment_says_so(unconfigured: TestClient) -> None:
    page = unconfigured.get("/login")
    assert page.status_code == 200
    # A sign-in button that redirects into a GitHub error page is the most
    # confusing possible way to be misconfigured.
    assert "not configured" in page.text
    assert "/auth/github/start" not in page.text


def test_the_sign_in_page_has_no_script(client: TestClient) -> None:
    page = client.get("/login")
    assert "<script" not in page.text.lower()
    assert "onclick" not in page.text.lower()


def test_an_unconfigured_start_does_not_redirect_off_site(unconfigured: TestClient) -> None:
    response = unconfigured.get("/auth/github/start")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# --- The callback -----------------------------------------------------------


def test_signing_in_creates_an_organisation_and_a_session(
    client: TestClient, database: Engine
) -> None:
    assert sign_in(client) == "/app"

    with database.connect() as connection:
        org = connection.execute(select(orgs).where(orgs.c.slug == "alice")).mappings().one()
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org["id"]}
        )
        user = connection.execute(select(users).where(users.c.org_id == org["id"])).mappings().one()
        assert user["provider_subject"] == ALICE.subject
        assert user["login"] == "alice"
        assert user["email"] == ALICE.email
        # Owner, because they created it. A new organisation whose only member
        # was a plain member would have nobody able to administer it.
        role = connection.execute(
            select(users_orgs.c.role).where(users_orgs.c.user_id == user["id"])
        ).scalar_one()
        assert role == "owner"
        assert (
            connection.execute(
                select(func.count()).select_from(sessions).where(sessions.c.org_id == org["id"])
            ).scalar_one()
            == 1
        )


def test_the_session_cookie_is_not_reachable_from_script_or_another_site(
    client: TestClient,
) -> None:
    start = client.get("/auth/github/start")
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    response = client.get("/auth/github/callback", params={"code": "alice-code", "state": state})

    header = response.headers["set-cookie"]
    assert tokens.COOKIE_NAME in header
    # Each of these removes a distinct attack, and the absence of any one is
    # invisible until it matters.
    assert "HttpOnly" in header
    assert "SameSite=lax" in header.replace("SameSite=Lax", "SameSite=lax")
    assert "Path=/" in header


def test_the_cookie_value_is_not_what_the_database_stores(
    client: TestClient, database: Engine
) -> None:
    sign_in(client)
    presented = client.cookies[tokens.COOKIE_NAME]
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == "alice")).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        stored = connection.execute(select(sessions.c.token_hash)).scalar_one()
    assert stored != presented
    assert stored == tokens.hash_token(presented)


def test_a_forged_state_does_not_sign_anybody_in(client: TestClient, database: Engine) -> None:
    response = client.get(
        "/auth/github/callback", params={"code": "alice-code", "state": "forged.state.value.here"}
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=state"
    assert tokens.COOKIE_NAME not in response.cookies
    with database.connect() as connection:
        # Nothing was created: the state is checked before the code is spent,
        # so an attacker's code is never exchanged at all.
        assert (
            connection.execute(
                select(func.count()).select_from(orgs).where(orgs.c.slug == "alice")
            ).scalar_one()
            == 0
        )


def test_a_missing_state_is_refused(client: TestClient) -> None:
    response = client.get("/auth/github/callback", params={"code": "alice-code"})
    assert response.headers["location"] == "/login?error=state"


def test_a_cancelled_authorisation_is_not_treated_as_a_fault(client: TestClient) -> None:
    response = client.get("/auth/github/callback", params={"error": "access_denied"})
    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=denied"
    page = client.get("/login?error=denied")
    assert "cancelled" in page.text


def test_a_provider_failure_lands_on_the_sign_in_page(client: TestClient) -> None:
    start = client.get("/auth/github/start")
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    response = client.get("/auth/github/callback", params={"code": "broken", "state": state})
    assert response.headers["location"] == "/login?error=provider"
    assert tokens.COOKIE_NAME not in response.cookies


def test_signing_in_twice_reuses_the_same_organisation(
    client: TestClient, database: Engine
) -> None:
    sign_in(client)
    sign_in(client)
    with database.connect() as connection:
        assert (
            connection.execute(
                select(func.count()).select_from(orgs).where(orgs.c.slug == "alice")
            ).scalar_one()
            == 1
        )


def test_a_renamed_account_keeps_its_identity(
    client: TestClient, database: Engine, provider: FakeProvider
) -> None:
    sign_in(client)
    # Same subject, new login. Keying on the login would make this a different
    # person, or worse, somebody else.
    provider.identities["alice-code"] = Identity(
        subject=ALICE.subject, login="alice-renamed", name="Alice", email=ALICE.email
    )
    sign_in(client)

    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == "alice")).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        rows = connection.execute(select(users.c.login)).scalars().all()
    assert rows == ["alice-renamed"]


def test_a_second_person_gets_their_own_organisation(client: TestClient, database: Engine) -> None:
    sign_in(client, "alice-code")
    sign_in(client, "bob-code")
    with database.connect() as connection:
        slugs = (
            connection.execute(select(orgs.c.slug).where(orgs.c.slug.in_(["alice", "bob"])))
            .scalars()
            .all()
        )
    assert sorted(slugs) == ["alice", "bob"]


def test_a_colliding_slug_is_made_unique(
    client: TestClient, database: Engine, provider: FakeProvider
) -> None:
    sign_in(client, "alice-code")
    # A different GitHub account that happens to be called alice.
    provider.identities["other"] = Identity(subject="9999", login="Alice", name=None, email=None)
    sign_in(client, "other")
    with database.connect() as connection:
        slugs = (
            connection.execute(select(orgs.c.slug).where(orgs.c.slug.like("alice%")))
            .scalars()
            .all()
        )
    # The slug appears in every public report URL, so a collision has to
    # resolve rather than fail.
    assert sorted(slugs) == ["alice", "alice-1"]


# --- Open redirects ---------------------------------------------------------


@pytest.mark.parametrize(
    "candidate",
    ["https://evil.example/", "//evil.example", "/\\evil.example", "http://evil.example"],
)
def test_sign_in_cannot_be_turned_into_an_open_redirect(client: TestClient, candidate: str) -> None:
    landed = sign_in(client, next_path=candidate)
    # "You were signed out, sign in again" phishing works precisely because
    # the link really does point at the real site.
    assert landed == "/app"


def test_a_local_return_path_is_honoured(client: TestClient) -> None:
    assert sign_in(client, next_path="/app/keys") == "/app/keys"


# --- The guards -------------------------------------------------------------


def test_a_signed_out_browser_is_sent_to_sign_in(client: TestClient) -> None:
    response = client.get("/app")
    assert response.status_code == 303
    # Carrying where they were going, so signing in resumes it rather than
    # dumping them on a dashboard.
    assert response.headers["location"] == "/login?next=%2Fapp"


def test_the_dashboard_renders_for_a_signed_in_browser(client: TestClient) -> None:
    sign_in(client)
    page = client.get("/app")
    assert page.status_code == 200
    assert "Alice Example" in page.text
    assert "<script" not in page.text.lower()


def test_an_api_key_does_not_open_the_dashboard(client: TestClient) -> None:
    sign_in(client)
    secret = _create_key(client)
    client.cookies.clear()
    response = client.get("/app", headers={"Authorization": f"Bearer {secret}"})
    # The HTML pages take a cookie and the JSON API takes a key. Accepting
    # either everywhere would give every endpoint the browser's problems.
    assert response.status_code == 303


def test_a_session_cookie_does_not_open_the_json_api(client: TestClient) -> None:
    sign_in(client)
    response = client.get("/v1/me")
    # No endpoint accepts both credentials, so no endpoint under /v1 can be
    # reached by a cross-site form submission carrying an ambient cookie.
    assert response.status_code == 401


def test_a_signed_out_cookie_stops_working(client: TestClient, database: Engine) -> None:
    sign_in(client)
    token = csrf_of(client)
    response = client.post("/logout", data={"csrf_token": token})
    assert response.status_code == 303

    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == "alice")).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        assert connection.execute(select(func.count()).select_from(sessions)).scalar_one() == 0


def test_signing_out_needs_the_csrf_token(client: TestClient, database: Engine) -> None:
    sign_in(client)
    response = client.post("/logout", data={})
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")
    # Still signed in: a sign-out any other site could trigger is a nuisance,
    # and an avoidable one.
    assert client.get("/app").status_code == 200


def test_a_csrf_token_from_another_session_is_refused(client: TestClient) -> None:
    sign_in(client, "alice-code")
    stolen = csrf_of(client)
    client.cookies.clear()
    sign_in(client, "bob-code")

    response = client.post("/app/projects", data={"csrf_token": stolen, "slug": "sneaky"})
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


# --- Projects ---------------------------------------------------------------


def test_creating_a_project_from_the_form(client: TestClient) -> None:
    sign_in(client)
    response = client.post("/app/projects", data={"csrf_token": csrf_of(client), "slug": "web"})
    assert response.status_code == 303
    assert client.get("/app").text.count("web") >= 1


def test_a_new_project_is_private(client: TestClient, database: Engine) -> None:
    sign_in(client)
    client.post("/app/projects", data={"csrf_token": csrf_of(client), "slug": "web"})
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == "alice")).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        visibility = connection.execute(select(projects.c.visibility)).scalar_one()
    # A default of public would publish a dependency inventory because
    # somebody did not read a field.
    assert visibility == "private"


def test_an_unusable_name_is_explained_rather_than_rejected_silently(client: TestClient) -> None:
    sign_in(client)
    response = client.post(
        "/app/projects", data={"csrf_token": csrf_of(client), "slug": "Not A Slug"}
    )
    assert response.status_code == 422
    # A sentence saying what to type, not the regular expression it failed.
    assert "lower-case letters" in response.text
    # What was typed is still on the screen rather than on an error page.
    assert "Add a project" in response.text


def test_a_duplicate_name_says_which(client: TestClient) -> None:
    sign_in(client)
    client.post("/app/projects", data={"csrf_token": csrf_of(client), "slug": "web"})
    response = client.post("/app/projects", data={"csrf_token": csrf_of(client), "slug": "web"})
    assert response.status_code == 422
    assert "already a project" in response.text


def test_creating_a_project_needs_the_csrf_token(client: TestClient, database: Engine) -> None:
    sign_in(client)
    client.post("/app/projects", data={"slug": "web"})
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == "alice")).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        assert connection.execute(select(func.count()).select_from(projects)).scalar_one() == 0


def test_publishing_and_unpublishing_a_project(client: TestClient) -> None:
    sign_in(client)
    client.post("/app/projects", data={"csrf_token": csrf_of(client), "slug": "web"})

    client.post(
        "/app/projects/web/visibility",
        data={"csrf_token": csrf_of(client), "visibility": "public"},
    )
    assert client.get("/p/alice/web").status_code == 200

    client.post(
        "/app/projects/web/visibility",
        data={"csrf_token": csrf_of(client), "visibility": "private"},
    )
    # Unpublishing withdraws the page entirely rather than leaving a stale
    # copy reachable.
    assert client.get("/p/alice/web").status_code == 404


def test_one_organisation_never_sees_another_s_projects(client: TestClient) -> None:
    sign_in(client, "alice-code")
    client.post("/app/projects", data={"csrf_token": csrf_of(client), "slug": "alice-only"})
    client.cookies.clear()

    sign_in(client, "bob-code")
    page = client.get("/app")
    assert page.status_code == 200
    assert "alice-only" not in page.text


# --- API keys ---------------------------------------------------------------


def _create_key(client: TestClient, name: str = "ci") -> str:
    response = client.post(
        "/app/keys", data={"csrf_token": csrf_of(client, "/app/keys"), "name": name}
    )
    assert response.status_code == 201, response.text
    match = re.search(r'value="(vexpath_live_[A-Za-z0-9_-]+)"', response.text)
    assert match is not None, "the new key was not shown"
    return match.group(1)


def test_a_new_key_is_shown_once_and_never_again(client: TestClient) -> None:
    sign_in(client)
    secret = _create_key(client)

    later = client.get("/app/keys")
    assert later.status_code == 200
    # Only the hash is stored, so this is not a policy that could be relaxed:
    # there is nothing left that could show it.
    assert secret not in later.text
    # The visible prefix is stored in the clear, so a person can tell two keys
    # apart without either of them being recoverable.
    assert apikeys.display_prefix(secret) in later.text


def test_the_keys_page_explains_that_the_secret_will_not_return(client: TestClient) -> None:
    sign_in(client)
    response = client.post("/app/keys", data={"csrf_token": csrf_of(client, "/app/keys")})
    assert "only time it is shown" in response.text


def test_a_key_created_in_the_browser_authenticates_the_command_line(
    client: TestClient,
) -> None:
    sign_in(client)
    secret = _create_key(client)

    # The whole product loop in three lines: the key from the page is the key
    # the tool uses. Until this passes, both halves work and the thing does
    # not.
    identity = client.get("/v1/me", headers={"Authorization": f"Bearer {secret}"})
    assert identity.status_code == 200, identity.text
    assert identity.json()["org_slug"] == "alice"
    assert identity.json()["actor_type"] == "api_key"


def test_a_revoked_key_stops_working(client: TestClient, database: Engine) -> None:
    sign_in(client)
    secret = _create_key(client)
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == "alice")).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        key_id = connection.execute(select(api_keys.c.id)).scalar_one()

    client.post(f"/app/keys/{key_id}/revoke", data={"csrf_token": csrf_of(client, "/app/keys")})
    assert client.get("/v1/me", headers={"Authorization": f"Bearer {secret}"}).status_code == 401


def test_creating_a_key_needs_the_csrf_token(client: TestClient, database: Engine) -> None:
    sign_in(client)
    client.post("/app/keys", data={"name": "forged"})
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == "alice")).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        assert connection.execute(select(func.count()).select_from(api_keys)).scalar_one() == 0


def test_a_key_belongs_to_the_organisation_that_created_it(client: TestClient) -> None:
    sign_in(client, "alice-code")
    alice_key = _create_key(client)
    client.cookies.clear()

    sign_in(client, "bob-code")
    page = client.get("/app/keys")
    assert alice_key[:20] not in page.text


def test_the_upload_loop_end_to_end(client: TestClient) -> None:
    """Sign in, create a project, issue a key, upload a scan with it.

    The acceptance criterion for this milestone, as one test. Each piece is
    covered on its own elsewhere; this asserts they join up, which is the part
    that silently fails when two halves are built a week apart.
    """
    sign_in(client)
    client.post("/app/projects", data={"csrf_token": csrf_of(client), "slug": "web"})
    secret = _create_key(client)

    upload = client.post(
        "/v1/scans",
        json={"project": "web", "results": _results()},
        headers={"Authorization": f"Bearer {secret}"},
    )
    assert upload.status_code == 201, upload.text

    page = client.get("/app")
    assert "web" in page.text
    # The scan is on the dashboard, counted, without anybody opening a
    # database client to check.
    assert "never" not in page.text


def _results() -> dict[str, Any]:
    """A results document, built through the model the analysis produces.

    Constructed rather than written out, so a change to the schema breaks this
    at the point of construction instead of surfacing as a 422 that looks like
    an upload problem.
    """
    from vexpath_core.enums import (
        ComponentScope,
        Confidence,
        ReachStatus,
        ScanMode,
        Severity,
        Verdict,
    )
    from vexpath_core.models.finding import (
        AdvisoryRef,
        ComponentRef,
        Finding,
        ReachabilityResult,
    )
    from vexpath_core.models.results import SbomRef, ScanResults

    finding = Finding(
        id="01JFINDING0000000000000000",
        advisory=AdvisoryRef(id="CVE-2026-0001", severity=Severity.HIGH),
        component=ComponentRef(
            purl="pkg:pypi/lib@1.0.0",
            ecosystem="PyPI",
            name="lib",
            version="1.0.0",
            direct=True,
            scope=ComponentScope.RUNTIME,
        ),
        verdict=Verdict.AFFECTED,
        reach=ReachabilityResult(
            status=ReachStatus.REACHABLE_CONFIRMED,
            confidence=Confidence.HIGH,
            matched_symbols=("lib.danger",),
            searched_symbols=("lib.danger",),
            explanation="reached from the entry point",
        ),
    )
    results = ScanResults(
        schema_version="vexpath.results/1",
        core_version="0.0.1",
        generated_at=datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
        mode=ScanMode.ACTION,
        advisory_snapshot_id="snap-1",
        sbom=SbomRef(format="cyclonedx-1.6-json", sha256="a" * 64, component_count=1),
        findings=(finding,),
    )
    parsed: dict[str, Any] = json.loads(results.model_dump_json(by_alias=True))
    return parsed
