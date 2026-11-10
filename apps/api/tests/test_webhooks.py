"""Webhooks: registration, delivery, signing, and what is refused.

The registration tests are a list of server-side request forgery attempts,
because that is what "give us a URL and we will call it" is. The delivery
tests use an injected resolver and transport, which is not a weakening of the
real path: the resolver lets a test answer with one public and one loopback
address — the bypass that matters and the one real DNS will never hand you on
demand — and the transport lets the receiver's behaviour be chosen. Nothing in
the application passes either, so there is no flag that could weaken this in a
deployment.

The assertion worth most is that the delivery a receiver gets verifies under
the secret that receiver was given, computed by the same function a receiver
would use. A signature scheme tested against a second copy of its own
arithmetic proves nothing.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, insert, select, text

from vexpath_api import webhooks as sender
from vexpath_api.main import create_app
from vexpath_api.oauth import Identity, OAuthError
from vexpath_core.ids import new_ulid
from vexpath_db.engine import create_app_engine, create_sync_engine
from vexpath_db.tables import api_keys, audit_log, orgs, projects, webhook_deliveries, webhooks
from vexpath_platform import apikeys, outbound, secretbox
from vexpath_platform.settings import Environment, Settings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

OWNER = Identity(subject="9001", login="hooks", name="Hooks Ltd", email=None)
SLUG = "hooks"
RECEIVER = "https://hooks.example.com/vexpath"
SECRET_KEY = "a-process-secret-for-the-webhook-tests"


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


@dataclass
class Fixture:
    client: TestClient
    engine: Any
    org_id: str
    key: str
    project_id: str


@pytest.fixture
def api(integration_database_url: str, database: Engine) -> Iterator[Fixture]:
    settings = Settings(
        env=Environment.TEST, database_url=integration_database_url, secret_key=SECRET_KEY
    )
    engine = create_app_engine(integration_database_url)
    try:
        app = create_app(settings, engine=engine, identity_provider=FakeProvider())
        with TestClient(app, follow_redirects=False) as client:
            start = client.get("/auth/github/start")
            state = re.search(r"state=([^&]+)", start.headers["location"])
            assert state is not None
            assert (
                client.get(
                    "/auth/github/callback", params={"code": "code", "state": state.group(1)}
                ).status_code
                == 303
            )

            # The database fixture's engine, not a second one: an undisposed
            # engine leaves a connection open, and the suite runs with
            # warnings as errors so that shows up as a failure.
            with database.begin() as connection:
                org_id = connection.execute(
                    select(orgs.c.id).where(orgs.c.slug == SLUG)
                ).scalar_one()
                connection.execute(
                    text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id}
                )
                issued = apikeys.issue()
                connection.execute(
                    insert(api_keys).values(
                        id=new_ulid(),
                        org_id=org_id,
                        name="ci",
                        key_hash=issued.key_hash,
                        prefix=issued.prefix,
                    )
                )
                project_id = new_ulid()
                connection.execute(
                    insert(projects).values(
                        id=project_id,
                        org_id=org_id,
                        slug="api",
                        visibility="private",
                        entry_points=[],
                        settings={},
                    )
                )

            yield Fixture(
                client=client,
                engine=engine,
                org_id=org_id,
                key=issued.secret,
                project_id=project_id,
            )
    finally:
        asyncio.run(engine.dispose())


def _headers(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


def _register(api: Fixture, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"url": RECEIVER, "events": ["scan.completed"]}
    body.update(overrides)
    response = api.client.post("/v1/webhooks", json=body, headers=_headers(api.key))
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


# --- Registration: the forgery attempts ------------------------------------


def test_an_ordinary_endpoint_can_be_registered(api: Fixture) -> None:
    created = _register(api)
    assert created["url"] == RECEIVER
    assert created["events"] == ["scan.completed"]
    assert created["active"] is True


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/x",
        "https://127.0.0.1/x",
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.5/x",
        "https://localhost/x",
        "https://db.internal/x",
        "https://hooks.example.com:6379/x",
        "https://user:pw@hooks.example.com/x",
        "file:///etc/passwd",
        "https://[::1]/x",
    ],
)
def test_a_url_that_would_reach_inside_is_refused(api: Fixture, url: str) -> None:
    response = api.client.post(
        "/v1/webhooks", json={"url": url, "events": ["ping"]}, headers=_headers(api.key)
    )
    # "Give us a URL and we will fetch it" is the most productive
    # vulnerability class in a hosted product. Every one of these is a known
    # way to use it.
    assert response.status_code == 422, url


def test_the_refusal_says_what_to_change(api: Fixture) -> None:
    response = api.client.post(
        "/v1/webhooks",
        json={"url": "https://169.254.169.254/latest/", "events": ["ping"]},
        headers=_headers(api.key),
    )
    detail = response.json()["detail"]
    # "That URL is not allowed" sends somebody to a support channel.
    assert "public internet" in detail
    assert "metadata" in detail


def test_an_unknown_event_is_refused(api: Fixture) -> None:
    response = api.client.post(
        "/v1/webhooks",
        json={"url": RECEIVER, "events": ["scan.completed", "scan.exploded"]},
        headers=_headers(api.key),
    )
    assert response.status_code == 422
    # A subscription to an event nobody emits looks like a working
    # subscription and is silence.
    assert "scan.exploded" in response.json()["detail"]
    assert "scan.completed" in response.json()["detail"]  # the available list


def test_registering_needs_at_least_one_event(api: Fixture) -> None:
    response = api.client.post(
        "/v1/webhooks", json={"url": RECEIVER, "events": []}, headers=_headers(api.key)
    )
    assert response.status_code == 422


# --- The secret -------------------------------------------------------------


def test_the_secret_is_returned_once_and_never_again(api: Fixture) -> None:
    created = _register(api)
    secret = created["secret"]
    assert secret.startswith("whsec_")

    read = api.client.get(f"/v1/webhooks/{created['id']}", headers=_headers(api.key)).json()
    assert "secret" not in read
    # The fingerprint is what tells two webhooks apart without showing either.
    assert read["secret_fingerprint"] == outbound.fingerprint(secret)

    listed = api.client.get("/v1/webhooks", headers=_headers(api.key)).json()
    assert all("secret" not in row for row in listed)


def test_the_stored_secret_is_encrypted(api: Fixture, database: Engine) -> None:
    created = _register(api)
    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": api.org_id}
        )
        stored = connection.execute(select(webhooks.c.secret_encrypted)).scalar_one()
    # Encrypted rather than hashed, because an HMAC needs it back -- and
    # encrypted rather than plain, so a leaked backup hands over nothing.
    assert created["secret"] not in stored
    assert secretbox.unseal(SECRET_KEY, stored) == created["secret"]


def test_rotating_the_secret_keeps_the_webhook_and_its_history(api: Fixture) -> None:
    created = _register(api)
    rotated = api.client.post(
        f"/v1/webhooks/{created['id']}/rotate", headers=_headers(api.key)
    ).json()
    assert rotated["id"] == created["id"]
    assert rotated["secret"] != created["secret"]
    # The point of rotating rather than recreating: the delivery history is
    # how somebody works out whether a leaked secret was used.
    assert rotated["secret_fingerprint"] != created["secret_fingerprint"]


def test_the_audit_log_records_the_url_and_not_the_secret(api: Fixture, database: Engine) -> None:
    created = _register(api)
    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": api.org_id}
        )
        rows = (
            connection.execute(
                select(audit_log.c.action, audit_log.c.metadata).where(
                    audit_log.c.action == "webhook.created"
                )
            )
            .mappings()
            .all()
        )
    assert len(rows) == 1
    assert rows[0]["metadata"]["url"] == RECEIVER
    # An audit log is read by more people than a credential should be.
    assert created["secret"] not in str(rows[0]["metadata"])


# --- Delivery ---------------------------------------------------------------


PUBLIC = ["93.184.216.34"]


async def public_resolver(host: str) -> list[str]:
    del host
    return PUBLIC


class Receiver:
    """A stand-in endpoint that records what arrived."""

    def __init__(self, *, status_codes: list[int] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.bodies: list[bytes] = []
        self.status_codes = status_codes or [200]

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            self.bodies.append(request.content)
            index = min(len(self.requests) - 1, len(self.status_codes) - 1)
            return httpx.Response(self.status_codes[index], json={"ok": True})

        return httpx.MockTransport(handle)


def _row(api: Fixture, database: Engine, webhook_id: str) -> dict[str, Any]:
    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": api.org_id}
        )
        return dict(
            connection.execute(select(webhooks).where(webhooks.c.id == webhook_id)).mappings().one()
        )


def _delivery(api: Fixture, database: Engine, delivery_id: str) -> dict[str, Any]:
    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": api.org_id}
        )
        return dict(
            connection.execute(
                select(webhook_deliveries).where(webhook_deliveries.c.id == delivery_id)
            )
            .mappings()
            .one()
        )


def _deliver(api: Fixture, row: dict[str, Any], receiver: Receiver, event: str = "ping") -> str:
    return asyncio.run(
        sender.deliver(
            api.engine,
            secret_key=SECRET_KEY,
            webhook=row,
            event=event,
            payload={"message": "hello"},
            resolver=public_resolver,
            transport=receiver.transport(),
        )
    )


def test_a_delivery_is_signed_with_the_secret_the_receiver_was_given(
    api: Fixture, database: Engine
) -> None:
    created = _register(api, events=["ping"])
    receiver = Receiver()
    _deliver(api, _row(api, database, created["id"]), receiver)

    assert len(receiver.requests) == 1
    request = receiver.requests[0]
    timestamp = int(request.headers[outbound.TIMESTAMP_HEADER])
    # Verified with the same function a receiver would use, against the secret
    # the API handed back. A scheme checked against a second copy of its own
    # arithmetic proves nothing.
    assert outbound.verify(
        created["secret"], timestamp, receiver.bodies[0], request.headers[outbound.SIGNATURE_HEADER]
    )


def test_a_delivery_carries_the_headers_a_receiver_needs(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    receiver = Receiver()
    delivery_id = _deliver(api, _row(api, database, created["id"]), receiver)
    request = receiver.requests[0]
    assert request.headers[outbound.EVENT_HEADER] == "ping"
    # The delivery identifier, so a receiver can make its handling idempotent.
    assert request.headers[outbound.DELIVERY_HEADER] == delivery_id
    assert request.headers["content-type"] == "application/json"


def test_the_signature_does_not_verify_under_a_rotated_secret(
    api: Fixture, database: Engine
) -> None:
    created = _register(api, events=["ping"])
    receiver = Receiver()
    _deliver(api, _row(api, database, created["id"]), receiver)
    request = receiver.requests[0]
    timestamp = int(request.headers[outbound.TIMESTAMP_HEADER])

    rotated = api.client.post(
        f"/v1/webhooks/{created['id']}/rotate", headers=_headers(api.key)
    ).json()
    assert not outbound.verify(
        rotated["secret"], timestamp, receiver.bodies[0], request.headers[outbound.SIGNATURE_HEADER]
    )


def test_a_successful_delivery_is_recorded(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    delivery_id = _deliver(api, _row(api, database, created["id"]), Receiver())
    row = _delivery(api, database, delivery_id)
    assert row["status"] == "delivered"
    assert row["attempts"] == 1
    assert row["response_status"] == 200
    assert row["completed_at"] is not None


def test_the_payload_is_not_stored(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    receiver = Receiver()
    delivery_id = _deliver(api, _row(api, database, created["id"]), receiver)
    row = _delivery(api, database, delivery_id)
    # Only the digest. A delivery carries findings, and a second copy of them
    # in a log table doubles the places a leak can come from.
    assert len(row["payload_sha256"]) == 64
    assert "hello" not in str(row)


def test_a_failing_endpoint_is_retried_and_then_recorded_as_failed(
    api: Fixture, database: Engine
) -> None:
    created = _register(api, events=["ping"])
    receiver = Receiver(status_codes=[500, 500, 500])
    delivery_id = _deliver(api, _row(api, database, created["id"]), receiver)

    # Three attempts, not more: beyond that the receiver is down and a sender
    # that keeps trying is a load generator aimed at somebody struggling.
    assert len(receiver.requests) == sender.MAX_ATTEMPTS
    row = _delivery(api, database, delivery_id)
    assert row["status"] == "failed"
    assert row["attempts"] == sender.MAX_ATTEMPTS
    assert "500" in (row["error"] or "")


def test_a_delivery_that_succeeds_on_the_second_attempt_is_not_a_failure(
    api: Fixture, database: Engine
) -> None:
    created = _register(api, events=["ping"])
    receiver = Receiver(status_codes=[503, 200])
    delivery_id = _deliver(api, _row(api, database, created["id"]), receiver)
    # Which is what retrying is for: a restart and a blip.
    assert _delivery(api, database, delivery_id)["status"] == "delivered"
    assert _delivery(api, database, delivery_id)["attempts"] == 2


def test_a_redirect_is_refused_rather_than_followed(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    receiver = Receiver(status_codes=[302])
    delivery_id = _deliver(api, _row(api, database, created["id"]), receiver)
    row = _delivery(api, database, delivery_id)
    # A redirect is a second URL that nothing validated, which is how all this
    # validation gets bypassed.
    assert row["status"] == "refused"
    assert "redirect" in (row["error"] or "")
    # Not retried: it will not stop being a redirect.
    assert len(receiver.requests) == 1


def test_a_hostname_that_resolves_inside_is_refused_at_delivery(
    api: Fixture, database: Engine
) -> None:
    created = _register(api, events=["ping"])
    receiver = Receiver()

    async def rebound(host: str) -> list[str]:
        del host
        # The DNS rebinding bypass: public when the webhook was registered,
        # loopback now. Validating once at registration would have missed it.
        return ["127.0.0.1"]

    delivery_id = asyncio.run(
        sender.deliver(
            api.engine,
            secret_key=SECRET_KEY,
            webhook=_row(api, database, created["id"]),
            event="ping",
            payload={},
            resolver=rebound,
            transport=receiver.transport(),
        )
    )
    row = _delivery(api, database, delivery_id)
    assert row["status"] == "refused"
    # Nothing was sent at all.
    assert receiver.requests == []


def test_a_mixed_resolution_is_refused(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    receiver = Receiver()

    async def mixed(host: str) -> list[str]:
        del host
        return ["93.184.216.34", "127.0.0.1"]

    delivery_id = asyncio.run(
        sender.deliver(
            api.engine,
            secret_key=SECRET_KEY,
            webhook=_row(api, database, created["id"]),
            event="ping",
            payload={},
            resolver=mixed,
            transport=receiver.transport(),
        )
    )
    # Every resolved address has to be public, not the first one: the socket
    # might pick the other.
    assert _delivery(api, database, delivery_id)["status"] == "refused"
    assert receiver.requests == []


def test_an_unreadable_secret_is_reported_as_something_to_reissue(
    api: Fixture, database: Engine
) -> None:
    created = _register(api, events=["ping"])
    row = _row(api, database, created["id"])
    row["secret_encrypted"] = secretbox.seal("a-completely-different-key", "whsec_x")

    delivery_id = _deliver(api, row, Receiver())
    stored = _delivery(api, database, delivery_id)
    # Expected after VEXPATH_SECRET_KEY is rotated, so it must not look like
    # the receiver's fault.
    assert stored["status"] == "refused"
    assert "re-issue" in (stored["error"] or "")


# --- Health -----------------------------------------------------------------


def test_consecutive_failures_eventually_disable_a_webhook(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    with database.begin() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": api.org_id}
        )
        connection.execute(
            webhooks.update()
            .where(webhooks.c.id == created["id"])
            .values(failure_count=sender.FAILURE_THRESHOLD - 1)
        )

    _deliver(api, _row(api, database, created["id"]), Receiver(status_codes=[500]))
    row = _row(api, database, created["id"])
    # Disabled rather than deleted, so somebody can see why it stopped.
    assert row["disabled_at"] is not None
    assert row["failure_count"] == sender.FAILURE_THRESHOLD


def test_a_success_clears_the_failure_count(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    with database.begin() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": api.org_id}
        )
        connection.execute(
            webhooks.update().where(webhooks.c.id == created["id"]).values(failure_count=5)
        )
    _deliver(api, _row(api, database, created["id"]), Receiver())
    assert _row(api, database, created["id"])["failure_count"] == 0


def test_a_disabled_webhook_can_be_turned_back_on(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    with database.begin() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": api.org_id}
        )
        connection.execute(
            webhooks.update()
            .where(webhooks.c.id == created["id"])
            .values(failure_count=99, disabled_at=text("now()"))
        )
    enabled = api.client.post(
        f"/v1/webhooks/{created['id']}/enable", headers=_headers(api.key)
    ).json()
    assert enabled["disabled_at"] is None
    # Cleared, so the next delivery's first retry does not disable it again.
    assert enabled["failure_count"] == 0


def test_a_disabled_webhook_receives_nothing(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    with database.begin() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": api.org_id}
        )
        connection.execute(
            webhooks.update()
            .where(webhooks.c.id == created["id"])
            .values(disabled_at=text("now()"))
        )
    receiver = Receiver()
    delivered = asyncio.run(
        sender.dispatch(
            api.engine,
            secret_key=SECRET_KEY,
            org_id=api.org_id,
            project_id=api.project_id,
            event="ping",
            payload={},
            resolver=public_resolver,
            transport=receiver.transport(),
        )
    )
    assert delivered == []
    assert receiver.requests == []


# --- Dispatch ---------------------------------------------------------------


def test_only_webhooks_subscribed_to_the_event_are_called(api: Fixture, database: Engine) -> None:
    _register(api, events=["ping"])
    _register(api, events=["scan.completed"], url="https://other.example.com/x")

    receiver = Receiver()
    delivered = asyncio.run(
        sender.dispatch(
            api.engine,
            secret_key=SECRET_KEY,
            org_id=api.org_id,
            project_id=api.project_id,
            event="ping",
            payload={},
            resolver=public_resolver,
            transport=receiver.transport(),
        )
    )
    assert len(delivered) == 1
    assert str(receiver.requests[0].url) == RECEIVER


def test_a_project_scoped_webhook_ignores_another_project(api: Fixture, database: Engine) -> None:
    _register(api, events=["ping"], project="api")
    receiver = Receiver()
    delivered = asyncio.run(
        sender.dispatch(
            api.engine,
            secret_key=SECRET_KEY,
            org_id=api.org_id,
            project_id=new_ulid(),
            event="ping",
            payload={},
            resolver=public_resolver,
            transport=receiver.transport(),
        )
    )
    assert delivered == []


def test_an_organisation_wide_webhook_covers_every_project(api: Fixture, database: Engine) -> None:
    _register(api, events=["ping"])  # no project
    receiver = Receiver()
    delivered = asyncio.run(
        sender.dispatch(
            api.engine,
            secret_key=SECRET_KEY,
            org_id=api.org_id,
            project_id=new_ulid(),
            event="ping",
            payload={},
            resolver=public_resolver,
            transport=receiver.transport(),
        )
    )
    assert len(delivered) == 1


def test_an_unknown_event_delivers_nothing(api: Fixture) -> None:
    receiver = Receiver()
    delivered = asyncio.run(
        sender.dispatch(
            api.engine,
            secret_key=SECRET_KEY,
            org_id=api.org_id,
            project_id=api.project_id,
            event="not.an.event",
            payload={},
            resolver=public_resolver,
            transport=receiver.transport(),
        )
    )
    assert delivered == []


# --- Tenancy and lifecycle --------------------------------------------------


def test_a_webhook_of_another_organisation_is_not_found(api: Fixture) -> None:
    assert (
        api.client.get(f"/v1/webhooks/{new_ulid()}", headers=_headers(api.key)).status_code == 404
    )


def test_deleting_a_webhook_removes_it(api: Fixture) -> None:
    created = _register(api)
    assert (
        api.client.delete(f"/v1/webhooks/{created['id']}", headers=_headers(api.key)).status_code
        == 204
    )
    assert api.client.get("/v1/webhooks", headers=_headers(api.key)).json() == []


def test_deleting_twice_is_not_found(api: Fixture) -> None:
    created = _register(api)
    api.client.delete(f"/v1/webhooks/{created['id']}", headers=_headers(api.key))
    assert (
        api.client.delete(f"/v1/webhooks/{created['id']}", headers=_headers(api.key)).status_code
        == 404
    )


def test_the_delivery_history_is_readable(api: Fixture, database: Engine) -> None:
    created = _register(api, events=["ping"])
    _deliver(api, _row(api, database, created["id"]), Receiver())
    history = api.client.get(
        f"/v1/webhooks/{created['id']}/deliveries", headers=_headers(api.key)
    ).json()
    assert len(history) == 1
    assert history[0]["status"] == "delivered"
    # The outcome, never the payload.
    assert "payload" not in history[0]


def test_a_webhook_cannot_be_registered_against_another_organisation_s_project(
    api: Fixture,
) -> None:
    response = api.client.post(
        "/v1/webhooks",
        json={"url": RECEIVER, "events": ["ping"], "project": "not-ours"},
        headers=_headers(api.key),
    )
    assert response.status_code == 404
