"""The scan and finding pages: the evidence behind a verdict.

What is tested here is not that the pages render. It is that they never show a
verdict without what it rests on, and never show three different situations as
if they were the same one:

- a path that was proven,
- a path that depends on a call resolved conservatively,
- and no analysis at all, which is not a clearance.

The last is the one that matters most. "Not reachable" and "nobody looked"
produce the same short list of things to fix, and treating them alike is how a
scanner ends up quietly hiding a real vulnerability.

Everything runs against real HTTP and a real database, through the sign-in
flow, because the pages are behind a session and the session is part of what
could go wrong.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

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
)
from vexpath_platform.settings import Environment, Settings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

ALICE = Identity(subject="7001", login="evidence", name="Evidence Ltd", email=None)
SLUG = "evidence"


@dataclass
class FakeProvider:
    """Enough of an identity provider to get a session."""

    identities: dict[str, Identity] = field(default_factory=lambda: {"code": ALICE})

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
            connection.execute(text("SELECT 1 FROM sessions LIMIT 1"))
    except Exception as exc:  # noqa: BLE001 - a missing database skips, not fails
        engine.dispose()
        pytest.skip(f"integration database unavailable: {type(exc).__name__}: {exc}")
    _wipe(engine)
    yield engine
    _wipe(engine)
    engine.dispose()


def _wipe(engine: Engine) -> None:
    with engine.begin() as connection:
        rows = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).all()
        for row in rows:
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
            # Signed in once per test: every page here is behind a session,
            # and driving the real flow keeps these tests honest about that.
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
    """Identifiers of the rows one test needs."""

    org_id: str
    project_id: str
    scan_id: str
    reachable: str
    cleared: str
    unanalysed: str


@pytest.fixture
def seeded(client: TestClient, database: Engine) -> Seeded:
    """A scan with one of each kind of finding.

    Three findings, deliberately: one reachable with a path, one cleared with
    searched symbols and no path, one with no reachability row at all. The
    third is what the pages must not render as a clearance.
    """
    with database.begin() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})

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
        scan_id = new_ulid()
        connection.execute(
            insert(scans).values(
                id=scan_id,
                org_id=org_id,
                project_id=project_id,
                mode="cli",
                git_ref="refs/heads/main",
                git_sha="c" * 40,
                core_version="0.0.1",
                status="completed",
                advisory_snapshot_id="snap-7",
                summary={"needs_attention": 2, "cleared": 1},
                created_at=datetime.now(UTC) - timedelta(minutes=5),
            )
        )
        sbom_id = new_ulid()
        connection.execute(
            insert(sboms).values(
                id=sbom_id,
                org_id=org_id,
                scan_id=scan_id,
                format="cyclonedx-1.6-json",
                document_hash="d" * 64,
                component_count=3,
            )
        )

        ids: dict[str, str] = {}
        for label, name in (
            ("reachable", "jinja2"),
            ("cleared", "urllib3"),
            ("unanalysed", "idna"),
        ):
            component_id = new_ulid()
            connection.execute(
                insert(components).values(
                    id=component_id,
                    org_id=org_id,
                    sbom_id=sbom_id,
                    purl=f"pkg:pypi/{name}@1.0.0",
                    ecosystem="PyPI",
                    name=name,
                    version="1.0.0",
                    direct=label == "reachable",
                    scope="runtime",
                    licenses=[],
                    hashes={},
                )
            )
            finding_id = new_ulid()
            ids[label] = finding_id
            connection.execute(
                insert(findings).values(
                    id=finding_id,
                    org_id=org_id,
                    scan_id=scan_id,
                    component_id=component_id,
                    advisory_id=f"CVE-2026-{len(ids):04d}",
                    severity="HIGH" if label == "reachable" else "MEDIUM",
                    kev=label == "reachable",
                    epss_score=0.42 if label == "reachable" else None,
                    verdict="not_affected" if label == "cleared" else "affected",
                    justification=(
                        "vulnerable_code_not_in_execute_path" if label == "cleared" else None
                    ),
                    fixed_in="2.0.0",
                    notes=[],
                )
            )

        connection.execute(
            insert(reachability_results).values(
                id=new_ulid(),
                org_id=org_id,
                finding_id=ids["reachable"],
                status="reachable_confirmed",
                confidence="high",
                matched_symbols=["jinja2.sandbox.unsafe"],
                searched_symbols=["jinja2.sandbox.unsafe", "jinja2.other"],
                shortest_path=[
                    {"symbol": "app.main:handler", "file": "app/main.py", "line": 11},
                    {
                        "symbol": "jinja2.sandbox.unsafe",
                        "file": "jinja2/sandbox.py",
                        "line": 402,
                        "edge_kind": "dynamic",
                    },
                ],
                path_count=3,
                via_dynamic_edges=True,
                entry_points={"source": "declared", "count": 2, "items": ["app.main:handler"]},
                graph_stats={
                    "first_party_nodes": 120,
                    "first_party_edges": 310,
                    "linked_packages": 7,
                    "unresolved_call_ratio": 0.12,
                    "parse_error_files": 1,
                },
                explanation="reached from app.main:handler through two calls",
            )
        )
        connection.execute(
            insert(reachability_results).values(
                id=new_ulid(),
                org_id=org_id,
                finding_id=ids["cleared"],
                status="unreachable",
                confidence="high",
                matched_symbols=[],
                searched_symbols=["urllib3.util.parse_url", "urllib3.connection.bad"],
                shortest_path=[],
                path_count=0,
                via_dynamic_edges=False,
                entry_points={"source": "inferred", "count": 4, "items": []},
                graph_stats={"first_party_nodes": 120, "unresolved_call_ratio": 0.03},
                explanation="no path from any of 4 entry points",
            )
        )

    return Seeded(
        org_id=org_id,
        project_id=project_id,
        scan_id=scan_id,
        reachable=ids["reachable"],
        cleared=ids["cleared"],
        unanalysed=ids["unanalysed"],
    )


# --- The project page -------------------------------------------------------


def test_the_project_page_lists_its_scans(client: TestClient, seeded: Seeded) -> None:
    page = client.get("/app/projects/api")
    assert page.status_code == 200
    assert seeded.scan_id in page.text
    assert "refs/heads/main" in page.text


def test_the_project_page_says_whether_a_scan_is_reproducible(
    client: TestClient, seeded: Seeded
) -> None:
    page = client.get("/app/projects/api")
    # A scan with no pinned corpus cannot have its verdicts re-derived, which
    # makes every clearance in it an assertion. The column exists to stop the
    # two kinds of scan looking alike.
    assert "Reproducible" in page.text


def test_a_project_of_another_organisation_is_not_found(client: TestClient) -> None:
    assert client.get("/app/projects/someone-elses").status_code == 404


def test_an_empty_project_explains_how_to_upload(client: TestClient, database: Engine) -> None:
    with database.begin() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        connection.execute(
            insert(projects).values(
                id=new_ulid(),
                org_id=org_id,
                slug="empty",
                visibility="private",
                entry_points=[],
                settings={},
            )
        )
    page = client.get("/app/projects/empty")
    assert page.status_code == 200
    assert "vexpath scan . --upload --project empty" in page.text


# --- The scan page ----------------------------------------------------------


def test_the_scan_page_puts_what_needs_attention_first(client: TestClient, seeded: Seeded) -> None:
    page = client.get(f"/app/scans/{seeded.scan_id}")
    assert page.status_code == 200
    # The ordering is the product. A list sorted by advisory identifier would
    # leave the reader to read all of it, which is what they came here to
    # avoid.
    assert page.text.index("Needs attention") < page.text.index("Cleared")
    assert page.text.index(seeded.reachable) < page.text.index(seeded.cleared)


def test_the_scan_page_shows_cleared_findings_rather_than_hiding_them(
    client: TestClient, seeded: Seeded
) -> None:
    page = client.get(f"/app/scans/{seeded.scan_id}")
    # "28 of your 38 findings cannot run" is exactly the claim that needs
    # checking, and a clearance nobody can see is one nobody can check.
    assert seeded.cleared in page.text
    assert "Cleared" in page.text


def test_the_scan_page_does_not_call_an_unanalysed_finding_unreachable(
    client: TestClient, seeded: Seeded
) -> None:
    page = client.get(f"/app/scans/{seeded.scan_id}")
    assert "not analysed" in page.text
    # The finding with no reachability row must not be in the cleared section.
    cleared_section = page.text[page.text.index("Cleared") :]
    assert seeded.unanalysed not in cleared_section


def test_the_scan_page_names_the_corpus_the_verdicts_came_from(
    client: TestClient, seeded: Seeded
) -> None:
    page = client.get(f"/app/scans/{seeded.scan_id}")
    assert "snap-7" in page.text


def test_a_scan_of_another_organisation_is_not_found(client: TestClient) -> None:
    assert client.get(f"/app/scans/{new_ulid()}").status_code == 404


# --- The finding page -------------------------------------------------------


def test_the_finding_page_renders_the_call_path_server_side(
    client: TestClient, seeded: Seeded
) -> None:
    page = client.get(f"/app/findings/{seeded.reachable}")
    assert page.status_code == 200
    # Hop by hop, with the file and line of each call, in the first response.
    # A path that arrived by script would be invisible to a crawler, a text
    # browser, and anybody reading a saved copy.
    assert "app.main:handler" in page.text
    assert "app/main.py:11" in page.text
    assert "jinja2/sandbox.py:402" in page.text
    assert '<ol class="call-path">' in page.text
    assert "<script" not in page.text.lower()


def test_a_conservatively_resolved_hop_is_marked(client: TestClient, seeded: Seeded) -> None:
    page = client.get(f"/app/findings/{seeded.reachable}")
    # One such hop is the difference between a proven path and a guess, and a
    # reader deciding whether to act deserves to know which they have.
    assert "dynamic call" in page.text
    assert "conservative" in page.text


def test_the_finding_page_lists_what_was_searched_for(client: TestClient, seeded: Seeded) -> None:
    page = client.get(f"/app/findings/{seeded.cleared}")
    assert page.status_code == 200
    # A clearance means "none of these could run". It is worth nothing unless
    # the reader can see which symbols "these" were.
    assert "urllib3.util.parse_url" in page.text
    assert "urllib3.connection.bad" in page.text
    assert "What was searched for" in page.text


def test_the_finding_page_names_the_entry_points(client: TestClient, seeded: Seeded) -> None:
    page = client.get(f"/app/findings/{seeded.cleared}")
    # Reachability is relative to where the search started. A finding
    # reachable only from a maintenance script is a different problem from one
    # reachable from a request handler.
    assert "Where the search started" in page.text
    assert "inferred" in page.text


def test_the_finding_page_publishes_the_quality_of_the_graph(
    client: TestClient, seeded: Seeded
) -> None:
    page = client.get(f"/app/findings/{seeded.reachable}")
    # So the verdict can be judged rather than trusted. A high unresolved
    # ratio means the graph could not see much.
    assert "Unresolved calls" in page.text
    assert "12.0%" in page.text


def test_an_unanalysed_finding_says_nobody_looked(client: TestClient, seeded: Seeded) -> None:
    page = client.get(f"/app/findings/{seeded.unanalysed}")
    assert page.status_code == 200
    # Not a clearance, and it must not look like one: "not reachable" and
    # "the question was not asked" produce the same short list, and conflating
    # them is how a scanner quietly hides a real vulnerability.
    assert "Nobody looked" in page.text
    assert "not the same as" in page.text
    assert "call-path" not in page.text


def test_the_finding_page_shows_the_exploitation_signals(
    client: TestClient, seeded: Seeded
) -> None:
    page = client.get(f"/app/findings/{seeded.reachable}")
    assert "exploited in the wild" in page.text  # KEV
    assert "0.420" in page.text  # EPSS


def test_a_finding_of_another_organisation_is_not_found(client: TestClient) -> None:
    assert client.get(f"/app/findings/{new_ulid()}").status_code == 404


def test_the_pages_are_behind_the_session(client: TestClient, seeded: Seeded) -> None:
    client.cookies.clear()
    for path in (
        "/app/projects/api",
        f"/app/scans/{seeded.scan_id}",
        f"/app/findings/{seeded.reachable}",
    ):
        response = client.get(path)
        assert response.status_code == 303, path
        assert response.headers["location"].startswith("/login")


def test_a_malformed_stored_path_does_not_break_the_page(
    client: TestClient, seeded: Seeded, database: Engine
) -> None:
    """A stored path is whatever a client uploaded.

    The upload is validated, but a row can also be written by an older build
    or edited by hand, and a template that indexed into it blindly would raise
    a 500 on the page a developer opens when something is already wrong.
    """
    with database.begin() as connection:
        connection.execute(
            text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": seeded.org_id}
        )
        connection.execute(
            reachability_results.update()
            .where(reachability_results.c.finding_id == seeded.reachable)
            .values(shortest_path=["not an object", {"no_symbol": True}, {"symbol": "ok.hop"}])
        )
    page = client.get(f"/app/findings/{seeded.reachable}")
    assert page.status_code == 200
    assert "ok.hop" in page.text
    assert "not an object" not in page.text


def test_the_scan_page_survives_a_scan_with_no_findings(
    client: TestClient, database: Engine
) -> None:
    with database.begin() as connection:
        org_id = connection.execute(select(orgs.c.id).where(orgs.c.slug == SLUG)).scalar_one()
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org_id})
        project_id = new_ulid()
        connection.execute(
            insert(projects).values(
                id=project_id,
                org_id=org_id,
                slug="clean",
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
                summary={},
            )
        )
    page = client.get(f"/app/scans/{scan_id}")
    assert page.status_code == 200
    # The ordinary state of a healthy project, and it must read as good news
    # rather than as a blank page.
    assert "Nothing in this scan needs attention" in page.text
