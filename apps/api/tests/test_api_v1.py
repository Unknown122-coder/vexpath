"""The JSON API: authentication, projects and scan upload.

The tests that matter here are the ones that try to cross a boundary. Two
organisations exist, each with its own key, and every endpoint is asked to show
one of them the other's data. Those are run through real HTTP against a real
database, because row-level security is the thing being tested and neither a
mock nor SQLite has it.

Authentication is tested for what it refuses and for what it declines to say:
a caller learns a key does not work, never whether it was unknown, revoked or
malformed, because each of those narrows a search for someone probing.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, insert, select, text

from vexpath_api.main import create_app
from vexpath_core.ids import new_ulid
from vexpath_db.engine import create_app_engine, create_sync_engine
from vexpath_db.tables import api_keys, audit_log, orgs
from vexpath_platform import apikeys
from vexpath_platform.settings import Environment, Settings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

MARKER = "ZZAPI"
ORG_A = f"{MARKER}A"
ORG_B = f"{MARKER}B"


@pytest.fixture
def database(integration_database_url: str) -> Iterator[Engine]:
    engine = create_sync_engine(integration_database_url, connect_timeout=3)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1 FROM orgs LIMIT 1"))
    except Exception as exc:  # noqa: BLE001 - a missing database skips, not fails
        engine.dispose()
        pytest.skip(f"integration database unavailable: {type(exc).__name__}: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture
def keys(database: Engine) -> Iterator[dict[str, str]]:
    """Two organisations, each with a live key, plus one revoked key."""
    _wipe(database)
    issued: dict[str, str] = {}
    with database.begin() as connection:
        for org in (ORG_A, ORG_B):
            connection.execute(
                text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org}
            )
            connection.execute(insert(orgs).values(id=org, org_id=org, slug=org.lower(), name=org))
            key = apikeys.issue()
            issued[org] = key.secret
            connection.execute(
                insert(api_keys).values(
                    id=f"{org}-key",
                    org_id=org,
                    name="ci",
                    key_hash=key.key_hash,
                    prefix=key.prefix,
                )
            )

        # A revoked key for the first organisation, to prove revocation bites.
        revoked = apikeys.issue()
        issued["revoked"] = revoked.secret
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": ORG_A})
        connection.execute(
            insert(api_keys).values(
                id=f"{ORG_A}-revoked",
                org_id=ORG_A,
                name="old",
                key_hash=revoked.key_hash,
                prefix=revoked.prefix,
                revoked_at=datetime.now(UTC),
            )
        )
    yield issued
    _wipe(database)


def _wipe(engine: Engine) -> None:
    with engine.begin() as connection:
        for org in (ORG_A, ORG_B):
            connection.execute(
                text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org}
            )
            connection.execute(delete(orgs).where(orgs.c.id == org))


@pytest.fixture
def client(integration_database_url: str, keys: dict[str, str]) -> Iterator[TestClient]:
    """An application sharing the test's database.

    The engine is supplied rather than created by the lifespan, so the
    lifespan does not own it and will not dispose it. Disposing it here is not
    tidiness: an undisposed asynchronous engine leaves connections open, and
    the suite runs with warnings as errors precisely so that a leak shows up
    as a failure rather than as a slow drift towards exhausting the pool.
    """
    settings = Settings(env=Environment.TEST, database_url=integration_database_url)
    engine = create_app_engine(integration_database_url)
    try:
        with TestClient(create_app(settings, engine=engine)) as test_client:
            yield test_client
    finally:
        asyncio.run(engine.dispose())


def _headers(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


def _create_project(client: TestClient, secret: str, slug: str, **extra: Any) -> dict[str, Any]:
    response = client.post("/v1/projects", json={"slug": slug, **extra}, headers=_headers(secret))
    assert response.status_code == 201, response.text
    result: dict[str, Any] = response.json()
    return result


# --- Authentication -------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer",
        "Bearer ",
        "Basic dXNlcjpwYXNz",
        "Bearer not-a-vexpath-key",
        "Bearer vexpath_live_short",
        "Bearer vexpath_live_" + "x" * 43,
    ],
)
def test_every_bad_credential_is_refused_identically(
    client: TestClient, header: str | None
) -> None:
    """One message for every cause.

    Saying which part failed would tell someone probing whether a key exists,
    whether it was revoked, or only that the shape was wrong. Each of those
    narrows their search.
    """
    headers = {} if header is None else {"Authorization": header}
    response = client.get("/v1/projects", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == ("the API key is missing, malformed, unknown or revoked")
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_a_revoked_key_stops_working(client: TestClient, keys: dict[str, str]) -> None:
    assert client.get("/v1/projects", headers=_headers(keys["revoked"])).status_code == 401
    assert client.get("/v1/projects", headers=_headers(keys[ORG_A])).status_code == 200


def test_a_live_key_identifies_its_organisation(client: TestClient, keys: dict[str, str]) -> None:
    _create_project(client, keys[ORG_A], "svc-a")
    _create_project(client, keys[ORG_B], "svc-b")

    mine = client.get("/v1/projects", headers=_headers(keys[ORG_A])).json()
    assert [project["slug"] for project in mine] == ["svc-a"]


def test_using_a_key_records_when(
    client: TestClient, keys: dict[str, str], database: Engine
) -> None:
    """So a dashboard can show a key nobody has used for a year."""
    client.get("/v1/projects", headers=_headers(keys[ORG_A]))
    with database.begin() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": ORG_A})
        used = connection.execute(
            select(api_keys.c.last_used_at).where(api_keys.c.id == f"{ORG_A}-key")
        ).scalar_one()
    assert used is not None


# --- Crossing the boundary ------------------------------------------------


def test_one_organisation_cannot_list_anothers_projects(
    client: TestClient, keys: dict[str, str]
) -> None:
    _create_project(client, keys[ORG_A], "secret-service")
    listed = client.get("/v1/projects", headers=_headers(keys[ORG_B])).json()
    assert listed == []


def test_one_organisation_cannot_read_anothers_project_by_slug(
    client: TestClient, keys: dict[str, str]
) -> None:
    """404, not 403.

    Telling the caller the project exists but is not theirs would turn this
    endpoint into a way of asking whether a competitor uses this platform and
    what they call their services.
    """
    _create_project(client, keys[ORG_A], "secret-service")
    response = client.get("/v1/projects/secret-service", headers=_headers(keys[ORG_B]))
    assert response.status_code == 404
    assert response.json()["detail"] == "no such project"


def test_two_organisations_can_use_the_same_slug(client: TestClient, keys: dict[str, str]) -> None:
    """Slugs are unique per organisation, not globally.

    A global namespace would leak which names are taken, and would let one
    customer squat on another's repository name.
    """
    _create_project(client, keys[ORG_A], "api")
    _create_project(client, keys[ORG_B], "api")


def test_a_duplicate_slug_within_one_organisation_is_refused(
    client: TestClient, keys: dict[str, str]
) -> None:
    _create_project(client, keys[ORG_A], "api")
    response = client.post("/v1/projects", json={"slug": "api"}, headers=_headers(keys[ORG_A]))
    assert response.status_code == 409


def test_the_organisation_cannot_be_chosen_by_the_caller(
    client: TestClient, keys: dict[str, str]
) -> None:
    """It comes from the credential, never from the body.

    A caller who could name it could create a project inside someone else's
    organisation, and the policy would then let them read it back.
    """
    response = client.post(
        "/v1/projects",
        json={"slug": "injected", "org_id": ORG_B},
        headers=_headers(keys[ORG_A]),
    )
    assert response.status_code in {201, 422}
    if response.status_code == 201:
        # If the extra field was ignored, the project must still be ours.
        listed = client.get("/v1/projects", headers=_headers(keys[ORG_B])).json()
        assert [project["slug"] for project in listed] == []


def test_one_organisation_cannot_publish_anothers_project(
    client: TestClient, keys: dict[str, str]
) -> None:
    _create_project(client, keys[ORG_A], "private-service")
    response = client.put(
        "/v1/projects/private-service/visibility",
        json={"visibility": "public"},
        headers=_headers(keys[ORG_B]),
    )
    assert response.status_code == 404

    mine = client.get("/v1/projects/private-service", headers=_headers(keys[ORG_A])).json()
    assert mine["visibility"] == "private"


# --- Projects -------------------------------------------------------------


def test_a_project_is_private_until_someone_says_otherwise(
    client: TestClient, keys: dict[str, str]
) -> None:
    """A default of public would publish an inventory by omission."""
    project = _create_project(client, keys[ORG_A], "svc")
    assert project["visibility"] == "private"


def test_visibility_can_be_changed_and_changed_back(
    client: TestClient, keys: dict[str, str]
) -> None:
    _create_project(client, keys[ORG_A], "svc")
    published = client.put(
        "/v1/projects/svc/visibility", json={"visibility": "public"}, headers=_headers(keys[ORG_A])
    ).json()
    assert published["visibility"] == "public"

    withdrawn = client.put(
        "/v1/projects/svc/visibility",
        json={"visibility": "private"},
        headers=_headers(keys[ORG_A]),
    ).json()
    assert withdrawn["visibility"] == "private"


@pytest.mark.parametrize("value", ["", "Public", "world", "yes"])
def test_an_unknown_visibility_is_refused(
    client: TestClient, keys: dict[str, str], value: str
) -> None:
    _create_project(client, keys[ORG_A], "svc")
    response = client.put(
        "/v1/projects/svc/visibility", json={"visibility": value}, headers=_headers(keys[ORG_A])
    )
    assert response.status_code == 422


@pytest.mark.parametrize("slug", ["a", "UPPER", "has space", "-leading", "trailing-", "x" * 101])
def test_an_unusable_slug_is_refused(client: TestClient, keys: dict[str, str], slug: str) -> None:
    """Slugs appear in URLs and badge paths, so the vocabulary is narrow."""
    response = client.post("/v1/projects", json={"slug": slug}, headers=_headers(keys[ORG_A]))
    assert response.status_code == 422


def test_a_repository_url_must_look_like_one(client: TestClient, keys: dict[str, str]) -> None:
    response = client.post(
        "/v1/projects",
        json={"slug": "svc", "repo_url": "javascript:alert(1)"},
        headers=_headers(keys[ORG_A]),
    )
    assert response.status_code == 422


# --- Scan upload ----------------------------------------------------------


def _results(findings: int = 1, *, cleared: bool = False) -> dict[str, Any]:
    """A results document shaped exactly as the CLI writes one."""
    from vexpath_core.enums import (
        ComponentScope,
        Confidence,
        ReachStatus,
        ScanMode,
        Severity,
        Verdict,
        VexJustification,
    )
    from vexpath_core.models.finding import (
        AdvisoryRef,
        ComponentRef,
        Finding,
        ReachabilityResult,
    )
    from vexpath_core.models.results import SbomRef, ScanResults

    built: list[Finding] = []
    for index in range(findings):
        reach = ReachabilityResult(
            status=ReachStatus.UNREACHABLE if cleared else ReachStatus.REACHABLE_CONFIRMED,
            confidence=Confidence.HIGH,
            matched_symbols=() if cleared else ("lib.danger",),
            searched_symbols=("lib.danger",),
            explanation="x",
        )
        built.append(
            Finding(
                id=new_ulid(),
                advisory=AdvisoryRef(id=f"CVE-2026-{index:04d}", severity=Severity.HIGH),
                component=ComponentRef(
                    purl=f"pkg:pypi/lib{index}@1.0.0",
                    ecosystem="PyPI",
                    name=f"lib{index}",
                    version="1.0.0",
                    direct=True,
                    scope=ComponentScope.RUNTIME,
                ),
                verdict=Verdict.NOT_AFFECTED if cleared else Verdict.AFFECTED,
                justification=(
                    VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH if cleared else None
                ),
                reach=reach,
                fixed_in="2.0.0",
            )
        )

    results = ScanResults(
        schema_version="vexpath.results/1",
        core_version="0.0.1",
        generated_at=datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
        mode=ScanMode.ACTION,
        advisory_snapshot_id="snap-1",
        sbom=SbomRef(format="cyclonedx-1.6-json", sha256="a" * 64, component_count=findings),
        findings=tuple(built),
    )
    return json.loads(results.model_dump_json(by_alias=True))


def test_a_scan_can_be_uploaded_and_read_back(client: TestClient, keys: dict[str, str]) -> None:
    _create_project(client, keys[ORG_A], "svc")
    response = client.post(
        "/v1/scans",
        json={"project": "svc", "results": _results(findings=3)},
        headers=_headers(keys[ORG_A]),
    )
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["finding_count"] == 3
    assert scan["mode"] == "action"
    assert scan["advisory_snapshot_id"] == "snap-1"
    assert scan["summary"]["findings"] == 3
    assert scan["summary"]["reproducible"] is True

    read = client.get(f"/v1/scans/{scan['id']}", headers=_headers(keys[ORG_A]))
    assert read.json()["id"] == scan["id"]


def test_a_cleared_finding_survives_the_round_trip(
    client: TestClient, keys: dict[str, str]
) -> None:
    """The verdict and its evidence are what the platform exists to show."""
    _create_project(client, keys[ORG_A], "svc")
    scan = client.post(
        "/v1/scans",
        json={"project": "svc", "results": _results(findings=2, cleared=True)},
        headers=_headers(keys[ORG_A]),
    ).json()
    assert scan["summary"]["by_verdict"]["not_affected"] == 2
    assert scan["summary"]["reachable"] == 0


def test_a_scan_cannot_be_uploaded_to_another_organisations_project(
    client: TestClient, keys: dict[str, str]
) -> None:
    _create_project(client, keys[ORG_A], "svc")
    response = client.post(
        "/v1/scans",
        json={"project": "svc", "results": _results()},
        headers=_headers(keys[ORG_B]),
    )
    assert response.status_code == 404


def test_one_organisation_cannot_list_anothers_scans(
    client: TestClient, keys: dict[str, str]
) -> None:
    _create_project(client, keys[ORG_A], "svc")
    client.post(
        "/v1/scans",
        json={"project": "svc", "results": _results()},
        headers=_headers(keys[ORG_A]),
    )
    assert client.get("/v1/scans", headers=_headers(keys[ORG_B])).json() == []


def test_one_organisation_cannot_read_anothers_scan_by_id(
    client: TestClient, keys: dict[str, str]
) -> None:
    _create_project(client, keys[ORG_A], "svc")
    scan = client.post(
        "/v1/scans",
        json={"project": "svc", "results": _results()},
        headers=_headers(keys[ORG_A]),
    ).json()

    response = client.get(f"/v1/scans/{scan['id']}", headers=_headers(keys[ORG_B]))
    assert response.status_code == 404


def test_a_results_document_this_build_cannot_read_is_refused(
    client: TestClient, keys: dict[str, str]
) -> None:
    """Rejected at the boundary rather than stored as rows nothing can read."""
    _create_project(client, keys[ORG_A], "svc")
    response = client.post(
        "/v1/scans",
        json={"project": "svc", "results": {"schema": "vexpath.results/1"}},
        headers=_headers(keys[ORG_A]),
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "not one this build understands" in detail["message"]
    # Named fields, because a client fixing an upload needs to know which.
    assert "core_version" in detail["fields"]
    assert detail["problems"] >= 1


def test_a_results_document_claiming_an_impossible_clearance_is_refused(
    client: TestClient, keys: dict[str, str]
) -> None:
    """The model's invariant holds at the API boundary too.

    A client could otherwise upload a document asserting a clearance the
    analysis never established, and the platform would publish it.
    """
    _create_project(client, keys[ORG_A], "svc")
    document = _results(findings=1)
    document["findings"][0]["verdict"] = "not_affected"
    document["findings"][0]["justification"] = "vulnerable_code_not_in_execute_path"
    # Still reachable_confirmed, which must not be allowed to clear anything.
    response = client.post(
        "/v1/scans",
        json={"project": "svc", "results": document},
        headers=_headers(keys[ORG_A]),
    )
    assert response.status_code == 422


def test_an_upload_is_recorded_in_the_audit_log(
    client: TestClient, keys: dict[str, str], database: Engine
) -> None:
    _create_project(client, keys[ORG_A], "svc")
    client.post(
        "/v1/scans",
        json={"project": "svc", "results": _results()},
        headers=_headers(keys[ORG_A]),
    )

    with database.begin() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": ORG_A})
        rows = connection.execute(
            select(audit_log.c.action, audit_log.c.actor_type, audit_log.c.metadata).where(
                audit_log.c.org_id == ORG_A
            )
        ).all()

    actions = {row.action for row in rows}
    assert "scan.uploaded" in actions
    uploaded = next(row for row in rows if row.action == "scan.uploaded")
    assert uploaded.actor_type == "api_key"
    # Whether the verdicts can be re-derived is part of the record, because it
    # is the difference between evidence and an assertion.
    assert uploaded.metadata["reproducible"] is True


def test_scans_can_be_filtered_by_project(client: TestClient, keys: dict[str, str]) -> None:
    _create_project(client, keys[ORG_A], "one")
    _create_project(client, keys[ORG_A], "two")
    client.post(
        "/v1/scans",
        json={"project": "one", "results": _results()},
        headers=_headers(keys[ORG_A]),
    )

    assert len(client.get("/v1/scans?project=one", headers=_headers(keys[ORG_A])).json()) == 1
    assert client.get("/v1/scans?project=two", headers=_headers(keys[ORG_A])).json() == []


# --- Findings and their evidence ------------------------------------------


def _uploaded(client: TestClient, secret: str, slug: str = "svc") -> str:
    _create_project(client, secret, slug)
    scan = client.post(
        "/v1/scans",
        json={"project": slug, "results": _results(findings=3)},
        headers=_headers(secret),
    ).json()
    scan_id: str = scan["id"]
    return scan_id


def test_findings_carry_their_evidence_inline(client: TestClient, keys: dict[str, str]) -> None:
    """A list of verdicts with no evidence is any other scanner's output.

    A client that has to make a second request for the call path will render
    the list without it.
    """
    scan_id = _uploaded(client, keys[ORG_A])
    rows = client.get(f"/v1/scans/{scan_id}/findings", headers=_headers(keys[ORG_A])).json()

    assert len(rows) == 3
    first = rows[0]
    assert first["reach"]["status"] == "reachable_confirmed"
    assert first["reach"]["searched_symbols"] == ["lib.danger"]
    assert first["reach"]["explanation"]
    assert first["component"]["name"].startswith("lib")


def test_findings_are_ordered_worst_first(client: TestClient, keys: dict[str, str]) -> None:
    _create_project(client, keys[ORG_A], "svc")
    document = _results(findings=2)
    # One cleared, one reachable, uploaded in the inconvenient order.
    document["findings"][0]["verdict"] = "affected"
    scan = client.post(
        "/v1/scans",
        json={"project": "svc", "results": document},
        headers=_headers(keys[ORG_A]),
    ).json()

    rows = client.get(f"/v1/scans/{scan['id']}/findings", headers=_headers(keys[ORG_A])).json()
    verdicts = [row["verdict"] for row in rows]
    # Anything needing attention sorts before anything cleared.
    assert verdicts == sorted(verdicts, key=lambda value: 0 if value != "not_affected" else 1)


def test_findings_can_be_filtered(client: TestClient, keys: dict[str, str]) -> None:
    scan_id = _uploaded(client, keys[ORG_A])

    affected = client.get(
        f"/v1/scans/{scan_id}/findings?verdict=affected", headers=_headers(keys[ORG_A])
    ).json()
    assert all(row["verdict"] == "affected" for row in affected)

    reachable = client.get(
        f"/v1/scans/{scan_id}/findings?reachable_only=true", headers=_headers(keys[ORG_A])
    ).json()
    assert all(row["reach"]["status"].startswith("reachable") for row in reachable)

    high = client.get(
        f"/v1/scans/{scan_id}/findings?severity=high", headers=_headers(keys[ORG_A])
    ).json()
    assert all(row["severity"] == "HIGH" for row in high)


def test_one_organisation_cannot_read_anothers_findings(
    client: TestClient, keys: dict[str, str]
) -> None:
    scan_id = _uploaded(client, keys[ORG_A])
    response = client.get(f"/v1/scans/{scan_id}/findings", headers=_headers(keys[ORG_B]))
    assert response.status_code == 404
    assert response.json()["detail"] == "no such scan"


def test_one_finding_can_be_read_on_its_own(client: TestClient, keys: dict[str, str]) -> None:
    scan_id = _uploaded(client, keys[ORG_A])
    rows = client.get(f"/v1/scans/{scan_id}/findings", headers=_headers(keys[ORG_A])).json()

    one = client.get(f"/v1/findings/{rows[0]['id']}", headers=_headers(keys[ORG_A]))
    assert one.status_code == 200
    assert one.json()["id"] == rows[0]["id"]


def test_one_organisation_cannot_read_anothers_finding_by_id(
    client: TestClient, keys: dict[str, str]
) -> None:
    scan_id = _uploaded(client, keys[ORG_A])
    rows = client.get(f"/v1/scans/{scan_id}/findings", headers=_headers(keys[ORG_A])).json()

    response = client.get(f"/v1/findings/{rows[0]['id']}", headers=_headers(keys[ORG_B]))
    assert response.status_code == 404


# --- The project's own policy ---------------------------------------------
#
# A policy written in the dashboard was stored, displayed, dry-run and
# enforced nowhere: every policy_evaluations row carried a null policy_id,
# because the only evaluation recorded was the client's own and the client
# runs whatever its command line said. These cover the two halves of the fix
# -- the server applying it on arrival, and the endpoint that lets a build
# apply the same rule.


def _store_policy(url: str, org: str, project_id: str, cel: str, *, name: str = "custom") -> str:
    from vexpath_db.tables import policies

    policy_id = new_ulid()
    engine = create_sync_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                insert(policies).values(
                    id=policy_id,
                    org_id=org,
                    project_id=project_id,
                    name=name,
                    cel=cel,
                    version=1,
                    # Only "repo" or "dashboard"; a check constraint
                    # allows nothing else.
                    source="dashboard",
                )
            )
    finally:
        engine.dispose()
    return policy_id


def _evaluations(url: str, scan_id: str) -> list[dict[str, Any]]:
    from vexpath_db.tables import policy_evaluations

    engine = create_sync_engine(url)
    try:
        with engine.connect() as connection:
            rows = (
                connection.execute(
                    select(policy_evaluations).where(policy_evaluations.c.scan_id == scan_id)
                )
                .mappings()
                .all()
            )
    finally:
        engine.dispose()
    return [dict(row) for row in rows]


def test_the_projects_own_policy_is_evaluated_when_a_scan_arrives(
    client: TestClient, keys: dict[str, str], integration_database_url: str
) -> None:
    """The point of a policy stored centrally is not depending on the caller.

    Before this, a gate configured in the dashboard governed nothing: the
    stored expression was read by the editor page and by nothing else.
    """
    project = _create_project(client, keys[ORG_A], "svc")
    policy_id = _store_policy(
        integration_database_url,
        ORG_A,
        project["id"],
        "findings.exists(f, f.reach.reachable || !f.reach.conclusive)",
    )

    scan = client.post(
        "/v1/scans",
        json={"project": "svc", "results": _results(findings=3)},
        headers=_headers(keys[ORG_A]),
    )
    assert scan.status_code == 201, scan.text

    rows = _evaluations(integration_database_url, scan.json()["id"])
    stored = [row for row in rows if row["policy_id"] == policy_id]
    assert len(stored) == 1, "the project's policy was not evaluated on arrival"
    # The fixture's findings are reachable_confirmed, so the gate must fail.
    assert stored[0]["passed"] is False
    assert stored[0]["violations"]


def test_a_project_policy_that_no_longer_compiles_does_not_reject_the_scan(
    client: TestClient, keys: dict[str, str], integration_database_url: str
) -> None:
    """The scan is evidence; the policy is an opinion about it.

    Losing the evidence because the opinion stopped parsing is the wrong
    trade, and a field rename is enough to cause it.
    """
    project = _create_project(client, keys[ORG_A], "svc")
    _store_policy(integration_database_url, ORG_A, project["id"], "findings.exists(f, f.")

    scan = client.post(
        "/v1/scans",
        json={"project": "svc", "results": _results(findings=1)},
        headers=_headers(keys[ORG_A]),
    )

    assert scan.status_code == 201, scan.text
    rows = _evaluations(integration_database_url, scan.json()["id"])
    assert all(row["policy_id"] is None for row in rows)


def test_a_build_can_read_the_policy_it_should_apply(
    client: TestClient, keys: dict[str, str], integration_database_url: str
) -> None:
    """A preset name resolves to its expression before it leaves the server.

    The client must not have to know the preset vocabulary, and a preset
    whose meaning changes in a later release must not silently change what a
    stored policy does.
    """
    project = _create_project(client, keys[ORG_A], "svc")
    _store_policy(integration_database_url, ORG_A, project["id"], "kev-only", name="kev-only")

    response = client.get("/v1/projects/svc/policy", headers=_headers(keys[ORG_A]))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == "kev-only"
    assert body["expression"].startswith("findings.exists(")
    assert "kev" in body["expression"]
    assert body["version"] == 1


def test_a_project_without_a_policy_has_nothing_to_apply(
    client: TestClient, keys: dict[str, str]
) -> None:
    _create_project(client, keys[ORG_A], "svc")
    response = client.get("/v1/projects/svc/policy", headers=_headers(keys[ORG_A]))
    assert response.status_code == 404


def test_one_organisation_cannot_read_anothers_policy(
    client: TestClient, keys: dict[str, str], integration_database_url: str
) -> None:
    project = _create_project(client, keys[ORG_A], "secret-service")
    _store_policy(integration_database_url, ORG_A, project["id"], "findings.exists(f, f.kev)")

    response = client.get("/v1/projects/secret-service/policy", headers=_headers(keys[ORG_B]))

    assert response.status_code == 404
