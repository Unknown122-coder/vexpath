"""The policy editor.

The test that matters most is not about the page at all. It asserts that the
variables a policy sees on this screen are exactly the variables it sees in
CI — same names, same nesting, same types. The platform keeps findings as rows
rather than the uploaded document and rebuilds the context from them, so a
field present in one builder and absent from the other would change what an
expression means between the two places it runs. An expression that errors is
a build failing for the wrong reason, which is the worst outcome a gate can
have.

The rest is about the two refusals: an expression that will not compile is
never stored, and an expression that cannot be evaluated against real
findings is reported as an error rather than as a pass.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, insert, select, text

from vexpath_api import policy_pages
from vexpath_api.main import create_app
from vexpath_api.oauth import Identity, OAuthError
from vexpath_core import policy as core_policy
from vexpath_core.ids import new_ulid
from vexpath_db.engine import create_app_engine, create_sync_engine
from vexpath_db.tables import (
    components,
    findings,
    orgs,
    policies,
    projects,
    reachability_results,
    sboms,
    scans,
)
from vexpath_platform.settings import Environment, Settings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

OWNER = Identity(subject="9701", login="gate", name="Gate Ltd", email=None)
SLUG = "gate"


# --- The parity test --------------------------------------------------------


def test_the_platform_sees_the_same_fields_a_policy_sees_in_ci() -> None:
    """The two context builders must agree, field for field.

    Built from a row shaped like the query's output rather than from a real
    database, so this runs as a unit test: it is about two dictionaries having
    the same keys, and a database would only make it slower to fail.
    """
    row = {
        "id": "01JFINDING",
        "advisory_id": "CVE-2026-0001",
        "severity": "HIGH",
        "cvss_v3_score": 7.5,
        "epss_score": 0.2,
        "kev": True,
        "verdict": "affected",
        "justification": None,
        "fixed_in": "2.0.0",
        "suppressed_by": None,
        "created_at": datetime.now(UTC),
        "component_name": "lib",
        "component_version": "1.0.0",
        "purl": "pkg:pypi/lib@1.0.0",
        "ecosystem": "PyPI",
        "direct": True,
        "scope": "runtime",
        "reach_status": "reachable_confirmed",
        "reach_reason": None,
        "reach_confidence": "high",
        "shortest_path": [{"symbol": "a"}, {"symbol": "b"}],
        "via_dynamic_edges": False,
    }
    entry = policy_pages._entry(row)

    assert set(entry) == set(core_policy.FINDING_FIELDS), (
        "the dashboard and the command line would disagree about what a policy can read"
    )
    assert set(entry["reach"]) == set(core_policy.REACH_FIELDS)


def test_no_field_a_policy_reads_is_ever_null() -> None:
    """A policy comparing against null errors at evaluation time.

    Which turns a reasonable expression into a broken build, so the absent
    values get the empty string, zero or false in both builders.
    """
    row = {
        "id": "01JFINDING",
        "advisory_id": "CVE-2026-0001",
        "severity": "UNKNOWN",
        "cvss_v3_score": None,
        "epss_score": None,
        "kev": False,
        "verdict": "under_investigation",
        "justification": None,
        "fixed_in": None,
        "suppressed_by": None,
        "created_at": datetime.now(UTC),
        "component_name": "lib",
        "component_version": "1.0.0",
        "purl": "pkg:pypi/lib@1.0.0",
        "ecosystem": "PyPI",
        "direct": False,
        "scope": "runtime",
        "reach_status": None,
        "reach_reason": None,
        "reach_confidence": None,
        "shortest_path": None,
        "via_dynamic_edges": False,
    }
    entry = policy_pages._entry(row)
    assert None not in entry.values()
    assert None not in entry["reach"].values()
    # And "nobody looked" is distinguishable from "not reachable", which is
    # the whole reason this field exists.
    assert entry["reach"]["analysed"] is False


def test_the_context_variables_are_the_documented_ones() -> None:
    assert set(core_policy.CONTEXT_VARIABLES) == {"findings", "scan", "project", "counts"}


# --- check() ----------------------------------------------------------------


def test_an_expression_that_does_not_compile_is_refused() -> None:
    resolved, problem = policy_pages.check("findings.exists(f, f.severity ==")
    assert resolved is None
    # Never stored. The next person to read the configuration would believe a
    # stored expression was a working gate.
    assert problem is not None
    assert "not valid CEL" in problem


def test_an_empty_expression_is_refused_with_the_alternative_named() -> None:
    resolved, problem = policy_pages.check("   ")
    assert resolved is None
    assert problem is not None
    assert "report-only" in problem


def test_an_absurdly_long_expression_is_refused() -> None:
    resolved, problem = policy_pages.check("false || " * 5000)
    assert resolved is None
    assert problem is not None


def test_a_preset_name_resolves_to_its_expression() -> None:
    resolved, problem = policy_pages.check("kev-only")
    assert problem is None
    # Stored as the expression, never the name: a preset whose meaning changed
    # in a later release would silently change what a project gates on.
    assert resolved == core_policy.PRESETS["kev-only"]


# --- dry_run ----------------------------------------------------------------


def _context(**overrides: Any) -> dict[str, Any]:
    entry = {
        "id": "01JFINDING",
        "advisory": "CVE-2026-0001",
        "aliases": [],
        "component": "lib",
        "purl": "pkg:pypi/lib@1.0.0",
        "ecosystem": "PyPI",
        "version": "1.0.0",
        "severity": "HIGH",
        "severity_rank": 3,
        "cvss": 7.5,
        "cvss_v4": 0.0,
        "epss": 0.2,
        "kev": False,
        "verdict": "affected",
        "justification": "",
        "fixed_in": "2.0.0",
        "has_fix": True,
        "age_days": 0,
        "scope": "runtime",
        "direct": True,
        "suppressed": False,
        "reach": {
            "analysed": True,
            "status": "reachable_confirmed",
            "reason": "",
            "confidence": "high",
            "confidence_rank": 3,
            "reachable": True,
            "path_length": 2,
            "via_dynamic_edges": False,
        },
    }
    entry.update(overrides)
    return {
        "findings": [entry],
        "scan": {
            "mode": "cli",
            "git_ref": "",
            "git_sha": "",
            "reproducible": True,
            "snapshot": "snap",
        },
        "project": {"slug": "svc"},
        "counts": {"affected": 1},
    }


def test_a_dry_run_says_a_gate_would_have_failed_and_why() -> None:
    outcome = policy_pages.dry_run(core_policy.PRESETS["balanced"], _context())
    assert outcome["ok"] is True
    assert outcome["passed"] is False
    # Naming the finding, not only the verdict: a report that says "failed" is
    # not actionable.
    assert outcome["violations"]
    assert "CVE-2026-0001" in outcome["violations"][0]["message"]
    assert outcome["violations"][0]["finding_id"] == "01JFINDING"


def test_a_dry_run_says_a_gate_would_have_passed() -> None:
    outcome = policy_pages.dry_run(
        core_policy.PRESETS["balanced"],
        _context(
            reach={
                "analysed": True,
                "status": "unreachable",
                "reason": "",
                "confidence": "high",
                "confidence_rank": 3,
                "reachable": False,
                "path_length": 0,
                "via_dynamic_edges": False,
            }
        ),
    )
    assert outcome["passed"] is True


def test_an_expression_that_cannot_be_evaluated_is_an_error_not_a_pass() -> None:
    # Reads a field no finding has. Reported as an error, for the same reason
    # the command line exits 3 on a broken policy: a gate that failed to run
    # must never look like a gate that was satisfied.
    outcome = policy_pages.dry_run("findings.exists(f, f.nonexistent == 1)", _context())
    assert outcome["ok"] is False
    assert outcome["error"]


def test_a_non_boolean_expression_is_an_error() -> None:
    outcome = policy_pages.dry_run('"not a boolean"', _context())
    assert outcome["ok"] is False
    assert "boolean" in outcome["error"]


# --- The page ---------------------------------------------------------------


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
            connection.execute(text("SELECT 1 FROM policies LIMIT 1"))
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


def csrf_of(client: TestClient, path: str) -> str:
    page = client.get(path)
    assert page.status_code == 200, page.text
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None
    return match.group(1)


@pytest.fixture
def project(client: TestClient, database: Engine) -> str:
    """A project with one scan holding one reachable high finding."""
    with database.begin() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
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
        scan_id = new_ulid()
        connection.execute(
            insert(scans).values(
                id=scan_id,
                org_id=org_id,
                project_id=project_id,
                core_version="0.0.1",
                status="completed",
                advisory_snapshot_id="snap-1",
                summary={},
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
                component_count=1,
            )
        )
        component_id = new_ulid()
        connection.execute(
            insert(components).values(
                id=component_id,
                org_id=org_id,
                sbom_id=sbom_id,
                purl="pkg:pypi/jinja2@3.1.0",
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
                advisory_id="CVE-2026-7777",
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
                shortest_path=[{"symbol": "app:main"}],
                path_count=1,
                via_dynamic_edges=False,
                explanation="reached",
            )
        )
    return "svc"


def test_the_page_shows_the_default_until_something_is_saved(
    client: TestClient, project: str
) -> None:
    page = client.get(f"/app/projects/{project}/policy")
    assert page.status_code == 200
    assert "Nothing saved yet" in page.text
    assert "balanced" in page.text
    assert "<script" not in page.text.lower()


def test_the_page_says_the_gate_runs_in_ci_not_here(client: TestClient, project: str) -> None:
    page = client.get(f"/app/projects/{project}/policy")
    # Inventing a server-side gate that silently disagreed with the one in CI
    # would be worse than having none, so the page says where it runs.
    assert "runs in CI, not here" in page.text
    assert "vexpath scan . --policy" in page.text


def test_the_page_dry_runs_the_default_against_the_last_scan(
    client: TestClient, project: str
) -> None:
    page = client.get(f"/app/projects/{project}/policy")
    # The reachable high finding fails the balanced preset, and the page says
    # so against the real scan rather than in the abstract.
    assert "Would have failed" in page.text
    assert "CVE-2026-7777" in page.text


def test_trying_an_expression_does_not_store_it(
    client: TestClient, project: str, database: Engine
) -> None:
    response = client.post(
        f"/app/projects/{project}/policy",
        data={
            "csrf_token": csrf_of(client, f"/app/projects/{project}/policy"),
            "expression": "false",
            "action": "try",
        },
    )
    assert response.status_code == 200
    assert "Would have passed" in response.text
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        assert connection.execute(select(policies)).mappings().all() == []


def test_saving_stores_the_expression_as_a_new_version(
    client: TestClient, project: str, database: Engine
) -> None:
    for expression in ("false", "findings.exists(f, f.kev)"):
        client.post(
            f"/app/projects/{project}/policy",
            data={
                "csrf_token": csrf_of(client, f"/app/projects/{project}/policy"),
                "expression": expression,
                "action": "save",
            },
        )
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        rows = connection.execute(select(policies).order_by(policies.c.version)).mappings().all()
    # A row each time rather than an edit: "who loosened the gate and when"
    # needs an answer months later.
    assert [row["version"] for row in rows] == [1, 2]
    assert rows[1]["cel"] == "findings.exists(f, f.kev)"


def test_saving_a_preset_stores_the_expression_not_the_name(
    client: TestClient, project: str, database: Engine
) -> None:
    client.post(
        f"/app/projects/{project}/policy",
        data={
            "csrf_token": csrf_of(client, f"/app/projects/{project}/policy"),
            "expression": "kev-only",
            "action": "save",
        },
    )
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        stored = connection.execute(select(policies.c.cel)).scalar_one()
    assert stored == core_policy.PRESETS["kev-only"]


def test_a_broken_expression_is_not_stored_and_says_why(
    client: TestClient, project: str, database: Engine
) -> None:
    response = client.post(
        f"/app/projects/{project}/policy",
        data={
            "csrf_token": csrf_of(client, f"/app/projects/{project}/policy"),
            "expression": "findings.exists(f, f.severity ==",
            "action": "save",
        },
    )
    assert response.status_code == 422
    assert "not valid CEL" in response.text
    # And the half-written expression is still in the box: losing it to a
    # validation error is the fastest way to make somebody stop using an
    # editor.
    assert "f.severity ==" in response.text

    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        assert connection.execute(select(policies)).mappings().all() == []


def test_saving_needs_the_csrf_token(client: TestClient, project: str, database: Engine) -> None:
    client.post(f"/app/projects/{project}/policy", data={"expression": "false", "action": "save"})
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        assert connection.execute(select(policies)).mappings().all() == []


def test_the_saved_expression_is_in_the_audit_log(
    client: TestClient, project: str, database: Engine
) -> None:
    from vexpath_db.tables import audit_log

    client.post(
        f"/app/projects/{project}/policy",
        data={
            "csrf_token": csrf_of(client, f"/app/projects/{project}/policy"),
            "expression": "false",
            "action": "save",
        },
    )
    with database.connect() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        row = (
            connection.execute(
                select(audit_log.c.metadata).where(audit_log.c.action == "policy.saved")
            )
            .mappings()
            .one()
        )
    # "false" is the loosest possible gate. If somebody sets it, that has to
    # be answerable later.
    assert row["metadata"]["cel"] == "false"
    assert row["metadata"]["version"] == 1


def test_a_project_without_scans_can_still_be_checked(client: TestClient, database: Engine) -> None:
    with database.begin() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        connection.execute(
            insert(projects).values(
                id=new_ulid(),
                org_id=org_id,
                slug="fresh",
                visibility="private",
                entry_points=[],
                settings={},
            )
        )
    page = client.get("/app/projects/fresh/policy")
    assert page.status_code == 200
    # Validity can be checked without effect, and the page says which.
    assert "Nothing to try it against" in page.text


def test_the_policy_page_of_another_organisation_is_not_found(client: TestClient) -> None:
    assert client.get("/app/projects/not-ours/policy").status_code == 404


def test_the_project_page_still_works_alongside_the_policy_route(
    client: TestClient, project: str
) -> None:
    # The project page matches a path-converted slug, which would swallow
    # "{slug}/policy" if it were registered first.
    page = client.get(f"/app/projects/{project}")
    assert page.status_code == 200
    assert "Scans of" in page.text or "No scans yet" in page.text
    assert f"/app/projects/{project}/policy" in page.text


def test_the_policy_page_is_behind_the_session(client: TestClient, project: str) -> None:
    client.cookies.clear()
    response = client.get(f"/app/projects/{project}/policy")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")
