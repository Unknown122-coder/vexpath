"""Suppressions, through the API and through the page.

Two properties are worth more than the rest, and both are about what a
suppression must *not* do.

**It must not become permanent.** A suppression with no expiry outlives the
reason for it, so there is no way to create one: the column is not nullable,
the duration is bounded, and the page shows how long is left. Somebody has to
look again, which is the only thing separating a suppression from a deletion.

**It must not change the facts.** It never rewrites a verdict, and it never
changes what the public report or the badge says about reachable code. A badge
reading "none reachable" because somebody suppressed the reachable one would be
the most misleading artefact this system could produce, so a test asserts the
badge after suppressing a reachable finding.
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

from vexpath_api import suppress
from vexpath_api.main import create_app
from vexpath_api.oauth import Identity, OAuthError
from vexpath_core.ids import new_ulid
from vexpath_db.engine import create_app_engine, create_sync_engine
from vexpath_db.tables import (
    api_keys,
    audit_log,
    components,
    findings,
    orgs,
    projects,
    reachability_results,
    sboms,
    scans,
    suppressions,
)
from vexpath_platform import apikeys
from vexpath_platform.settings import Environment, Settings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

OWNER = Identity(subject="8001", login="suppress", name="Suppress Co", email=None)
SLUG = "suppress"
ADVISORY = "CVE-2026-9001"
PURL = "pkg:pypi/jinja2@3.1.0"


# --- Unit: the rules, without a database ------------------------------------


def test_a_suppression_needs_a_reason() -> None:
    with pytest.raises(suppress.SuppressionError, match="needs a reason"):
        suppress.build(advisory_id=ADVISORY, reason="   ")


def test_a_suppression_cannot_run_forever() -> None:
    with pytest.raises(suppress.SuppressionError, match="at most"):
        suppress.build(advisory_id=ADVISORY, reason="later", days=5000)


def test_a_suppression_cannot_be_zero_length() -> None:
    with pytest.raises(suppress.SuppressionError, match="at least"):
        suppress.build(advisory_id=ADVISORY, reason="later", days=0)


def test_the_default_duration_is_bounded_and_explained() -> None:
    request = suppress.build(advisory_id=ADVISORY, reason="later")
    assert 89 <= (request.expires_at - datetime.now(UTC)).days <= 90
    assert suppress.DEFAULT_DAYS == 90


def test_an_empty_purl_means_the_whole_project() -> None:
    # The broader and more dangerous choice, so it is never arrived at by
    # leaving a field blank in a client: blank means blank.
    assert suppress.build(advisory_id=ADVISORY, reason="x", purl="  ").purl is None
    assert suppress.build(advisory_id=ADVISORY, reason="x", purl=PURL).purl == PURL


def _row(**overrides: Any) -> dict[str, Any]:
    row = {
        "advisory_id": ADVISORY,
        "purl": PURL,
        "revoked_at": None,
        "expires_at": datetime.now(UTC) + timedelta(days=5),
    }
    row.update(overrides)
    return row


def test_an_expired_suppression_no_longer_applies() -> None:
    # Nothing deletes an expired row -- the history is worth keeping -- so a
    # row that lingers must not keep working.
    assert not suppress.is_active(_row(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    assert suppress.is_active(_row())


def test_a_revoked_suppression_no_longer_applies() -> None:
    assert not suppress.is_active(_row(revoked_at=datetime.now(UTC)))


def test_matching_is_exact_on_the_component() -> None:
    row = _row()
    assert suppress.matches(row, advisory_id=ADVISORY, purl=PURL)
    # A prefix match would let a suppression written for one package quietly
    # cover a package added later whose name starts the same way.
    assert not suppress.matches(row, advisory_id=ADVISORY, purl="pkg:pypi/jinja2-extra@1.0.0")
    assert not suppress.matches(row, advisory_id="CVE-2026-0000", purl=PURL)


def test_a_project_wide_suppression_covers_every_component() -> None:
    assert suppress.matches(_row(purl=None), advisory_id=ADVISORY, purl="pkg:pypi/anything@1")


def test_the_most_specific_suppression_wins() -> None:
    narrow = _row(purl=PURL, expires_at=datetime.now(UTC) + timedelta(days=30))
    broad = _row(purl=None, expires_at=datetime.now(UTC) + timedelta(days=1))
    chosen = suppress.applicable([broad, narrow], advisory_id=ADVISORY, purl=PURL)
    # So revoking the broad one does not silently unsuppress something that
    # had its own entry.
    assert chosen is narrow


def test_remaining_days_never_goes_negative() -> None:
    assert suppress.remaining_days(_row(expires_at=datetime.now(UTC) - timedelta(days=9))) == 0


# --- Integration ------------------------------------------------------------


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
            connection.execute(text("SELECT 1 FROM suppressions LIMIT 1"))
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
    settings = Settings(env=Environment.TEST, database_url=integration_database_url)
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


@dataclass
class Seeded:
    org_id: str
    key: str
    project_id: str
    scan_id: str
    finding_id: str


@pytest.fixture
def seeded(client: TestClient, database: Engine) -> Seeded:
    """A published project with one reachable finding, and an API key."""
    with database.begin() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})

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
                # Published, so the badge can be asked what it says after a
                # suppression. That is the assertion that matters most here.
                visibility="public",
                entry_points=[],
                settings={},
            )
        )
        scan_id = new_ulid()
        connection.execute(
            insert(scans).values(
                id=scan_id,
                org_id=org_id,
                project_id=project_id,
                core_version="0.0.1",
                status="completed",
                advisory_snapshot_id="snap-9",
                summary={"reachable": 1, "needs_attention": 1, "cleared": 0},
            )
        )
        sbom_id = new_ulid()
        connection.execute(
            insert(sboms).values(
                id=sbom_id,
                org_id=org_id,
                scan_id=scan_id,
                format="cyclonedx-1.6-json",
                document_hash="e" * 64,
                component_count=1,
            )
        )
        component_id = new_ulid()
        connection.execute(
            insert(components).values(
                id=component_id,
                org_id=org_id,
                sbom_id=sbom_id,
                purl=PURL,
                ecosystem="PyPI",
                name="jinja2",
                version="3.1.0",
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
                advisory_id=ADVISORY,
                severity="HIGH",
                verdict="affected",
                notes=[],
            )
        )
        connection.execute(
            insert(reachability_results).values(
                id=new_ulid(),
                org_id=org_id,
                finding_id=finding_id,
                status="reachable_confirmed",
                confidence="high",
                matched_symbols=["jinja2.bad"],
                searched_symbols=["jinja2.bad"],
                shortest_path=[{"symbol": "app:main"}, {"symbol": "jinja2.bad"}],
                path_count=1,
                via_dynamic_edges=False,
                explanation="reached",
            )
        )

    return Seeded(
        org_id=org_id,
        key=issued.secret,
        project_id=project_id,
        scan_id=scan_id,
        finding_id=finding_id,
    )


def csrf_of(client: TestClient, path: str) -> str:
    page = client.get(path)
    assert page.status_code == 200, page.text
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None
    return match.group(1)


def _headers(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


# --- The API ----------------------------------------------------------------


def test_the_api_records_a_suppression(client: TestClient, seeded: Seeded) -> None:
    response = client.post(
        "/v1/suppressions",
        json={
            "project": "api",
            "advisory_id": ADVISORY,
            "purl": PURL,
            "reason": "upgrade blocked on the 3.0 migration, PLAT-412",
            "days": 30,
        },
        headers=_headers(seeded.key),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["active"] is True
    assert 29 <= body["expires_in_days"] <= 30
    assert body["reason"].startswith("upgrade blocked")


def test_the_api_refuses_a_suppression_with_no_reason(client: TestClient, seeded: Seeded) -> None:
    response = client.post(
        "/v1/suppressions",
        json={"project": "api", "advisory_id": ADVISORY, "reason": "   "},
        headers=_headers(seeded.key),
    )
    assert response.status_code == 422
    assert "review" in response.json()["detail"]


def test_the_api_refuses_a_suppression_that_never_expires_in_practice(
    client: TestClient, seeded: Seeded
) -> None:
    response = client.post(
        "/v1/suppressions",
        json={"project": "api", "advisory_id": ADVISORY, "reason": "forever", "days": 4000},
        headers=_headers(seeded.key),
    )
    assert response.status_code == 422
    assert "formality" in response.json()["detail"]


def test_the_api_hides_expired_suppressions_by_default(
    client: TestClient, seeded: Seeded, database: Engine
) -> None:
    with database.begin() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": seeded.org_id}
        )
        connection.execute(
            insert(suppressions).values(
                id=new_ulid(),
                org_id=seeded.org_id,
                project_id=seeded.project_id,
                advisory_id=ADVISORY,
                reason="was fine at the time",
                expires_at=datetime.now(UTC) - timedelta(days=1),
            )
        )
    assert client.get("/v1/suppressions", headers=_headers(seeded.key)).json() == []
    # Available on request, because "how long has this been ignored" is a
    # question the history answers and a tidy table does not.
    stale = client.get(
        "/v1/suppressions", params={"include_inactive": True}, headers=_headers(seeded.key)
    ).json()
    assert len(stale) == 1
    assert stale[0]["active"] is False


def test_the_api_revokes_a_suppression(client: TestClient, seeded: Seeded) -> None:
    created = client.post(
        "/v1/suppressions",
        json={"project": "api", "advisory_id": ADVISORY, "reason": "temporary"},
        headers=_headers(seeded.key),
    ).json()
    revoked = client.delete(f"/v1/suppressions/{created['id']}", headers=_headers(seeded.key))
    assert revoked.status_code == 200
    assert revoked.json()["active"] is False
    # Marked, not deleted: suppressed-for-five-months-then-not is a different
    # situation from never-suppressed, and only the first is worth discussing.
    assert (
        client.get(
            "/v1/suppressions", params={"include_inactive": True}, headers=_headers(seeded.key)
        ).json()[0]["revoked_at"]
        is not None
    )


def test_revoking_twice_is_not_found(client: TestClient, seeded: Seeded) -> None:
    created = client.post(
        "/v1/suppressions",
        json={"project": "api", "advisory_id": ADVISORY, "reason": "temporary"},
        headers=_headers(seeded.key),
    ).json()
    client.delete(f"/v1/suppressions/{created['id']}", headers=_headers(seeded.key))
    assert (
        client.delete(f"/v1/suppressions/{created['id']}", headers=_headers(seeded.key)).status_code
        == 404
    )


def test_a_suppression_for_another_organisation_s_project_is_not_found(
    client: TestClient, seeded: Seeded
) -> None:
    response = client.post(
        "/v1/suppressions",
        json={"project": "somebody-elses", "advisory_id": ADVISORY, "reason": "x"},
        headers=_headers(seeded.key),
    )
    assert response.status_code == 404


def test_every_suppression_is_written_to_the_audit_log(
    client: TestClient, seeded: Seeded, database: Engine
) -> None:
    client.post(
        "/v1/suppressions",
        json={"project": "api", "advisory_id": ADVISORY, "reason": "deferred to Q3"},
        headers=_headers(seeded.key),
    )
    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": seeded.org_id}
        )
        rows = (
            connection.execute(
                select(audit_log.c.action, audit_log.c.metadata).where(
                    audit_log.c.action == "suppression.created"
                )
            )
            .mappings()
            .all()
        )
    assert len(rows) == 1
    # "Who decided not to fix this, and what did they say at the time" cannot
    # be answered by a row that only holds the current state.
    assert rows[0]["metadata"]["reason"] == "deferred to Q3"


# --- A suppression does not change the facts --------------------------------


def test_the_badge_still_reports_reachable_code_after_a_suppression(
    client: TestClient, seeded: Seeded
) -> None:
    before = client.get(f"/badge/{SLUG}/api.svg")
    assert "1 reachable" in before.text

    client.post(
        "/v1/suppressions",
        json={"project": "api", "advisory_id": ADVISORY, "purl": PURL, "reason": "deferred"},
        headers=_headers(seeded.key),
    )

    after = client.get(f"/badge/{SLUG}/api.svg")
    # A badge saying "none reachable" because somebody suppressed the
    # reachable one would be the most misleading thing this system could
    # produce. Suppression is a decision about work, not a change to facts.
    assert "1 reachable" in after.text


def test_the_finding_keeps_its_verdict_and_evidence(client: TestClient, seeded: Seeded) -> None:
    client.post(
        "/v1/suppressions",
        json={"project": "api", "advisory_id": ADVISORY, "purl": PURL, "reason": "deferred"},
        headers=_headers(seeded.key),
    )
    page = client.get(f"/app/findings/{seeded.finding_id}")
    assert page.status_code == 200
    assert "Suppressed" in page.text
    # The evidence is exactly as it was.
    assert "jinja2.bad" in page.text
    assert "call-path" in page.text


# --- The page ---------------------------------------------------------------


def test_suppressing_from_the_finding_page(
    client: TestClient, seeded: Seeded, database: Engine
) -> None:
    token = csrf_of(client, f"/app/findings/{seeded.finding_id}")
    response = client.post(
        f"/app/findings/{seeded.finding_id}/suppress",
        data={"csrf_token": token, "reason": "waiting on upstream release", "days": "45"},
    )
    assert response.status_code == 303

    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": seeded.org_id}
        )
        row = connection.execute(select(suppressions)).mappings().one()
    # Scoped to this component by default: a project-wide suppression also
    # covers packages added next month, which is a bigger decision than the
    # button it would otherwise share.
    assert row["purl"] == PURL
    assert row["reason"] == "waiting on upstream release"


def test_the_whole_project_option_widens_the_scope(
    client: TestClient, seeded: Seeded, database: Engine
) -> None:
    token = csrf_of(client, f"/app/findings/{seeded.finding_id}")
    client.post(
        f"/app/findings/{seeded.finding_id}/suppress",
        data={"csrf_token": token, "reason": "whole fleet", "whole_project": "yes"},
    )
    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": seeded.org_id}
        )
        assert connection.execute(select(suppressions.c.purl)).scalar_one() is None


def test_the_page_refuses_a_suppression_with_no_reason(
    client: TestClient, seeded: Seeded, database: Engine
) -> None:
    token = csrf_of(client, f"/app/findings/{seeded.finding_id}")
    response = client.post(
        f"/app/findings/{seeded.finding_id}/suppress",
        data={"csrf_token": token, "reason": "  "},
    )
    assert response.status_code == 303
    assert "problem=reason" in response.headers["location"]

    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": seeded.org_id}
        )
        assert connection.execute(select(suppressions)).mappings().all() == []

    page = client.get(f"/app/findings/{seeded.finding_id}?problem=reason")
    assert "cannot be reviewed" in page.text


def test_the_page_will_not_echo_text_from_the_query_string(
    client: TestClient, seeded: Seeded
) -> None:
    page = client.get(
        f"/app/findings/{seeded.finding_id}",
        params={"problem": "Your account was closed. Call 0800 123 456 to restore it."},
    )
    assert page.status_code == 200
    # A sentence taken from a URL and rendered on a page is how a phishing
    # message gets hosted on somebody else's domain. Autoescaping stops the
    # markup, not the sentence, so the vocabulary is closed instead.
    assert "0800 123 456" not in page.text


def test_suppressing_needs_the_csrf_token(
    client: TestClient, seeded: Seeded, database: Engine
) -> None:
    client.post(f"/app/findings/{seeded.finding_id}/suppress", data={"reason": "forged"})
    with database.connect() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": seeded.org_id}
        )
        assert connection.execute(select(suppressions)).mappings().all() == []


def test_the_page_shows_when_a_suppression_expires(client: TestClient, seeded: Seeded) -> None:
    token = csrf_of(client, f"/app/findings/{seeded.finding_id}")
    client.post(
        f"/app/findings/{seeded.finding_id}/suppress",
        data={"csrf_token": token, "reason": "deferred", "days": "10"},
    )
    page = client.get(f"/app/findings/{seeded.finding_id}")
    # "expires in 9 days" is a prompt to do something; a date is just a date.
    assert "expires in 9 days" in page.text or "expires in 10 days" in page.text


def test_bringing_a_suppressed_finding_back(client: TestClient, seeded: Seeded) -> None:
    token = csrf_of(client, f"/app/findings/{seeded.finding_id}")
    client.post(
        f"/app/findings/{seeded.finding_id}/suppress",
        data={"csrf_token": token, "reason": "deferred"},
    )
    page = client.get(f"/app/findings/{seeded.finding_id}")
    match = re.search(r'action="/app/suppressions/([^/]+)/revoke"', page.text)
    assert match is not None

    token = csrf_of(client, f"/app/findings/{seeded.finding_id}")
    response = client.post(
        f"/app/suppressions/{match.group(1)}/revoke",
        data={"csrf_token": token, "finding": seeded.finding_id},
    )
    assert response.status_code == 303
    assert "Suppressed" not in client.get(f"/app/findings/{seeded.finding_id}").text


def test_suppressing_a_finding_of_another_organisation_is_not_found(
    client: TestClient, seeded: Seeded
) -> None:
    token = csrf_of(client, f"/app/findings/{seeded.finding_id}")
    response = client.post(
        f"/app/findings/{new_ulid()}/suppress", data={"csrf_token": token, "reason": "x"}
    )
    assert response.status_code == 404
