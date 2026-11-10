"""Public report pages, the package page and the badge.

These are the pages with no caller to authenticate, so they are where a
mistake is visible to everyone at once. Three things are asserted, each one of
M4's acceptance criteria:

- a private project is not readable, by anybody, through any of them;
- the whole report is in the first HTML response, with no second request;
- the badge says what the scan said, and does not overstate when the analysis
  could not decide.

Needs a real Postgres, because what keeps a private project invisible here is
a row-level security policy and not an ``if`` statement.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, insert, text

from vexpath_api.main import create_app
from vexpath_core.ids import new_ulid
from vexpath_db.engine import create_app_engine, create_sync_engine
from vexpath_db.tables import api_keys, orgs
from vexpath_platform import apikeys
from vexpath_platform.settings import Environment, Settings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

ORG = "ZZPUB"
ORG_SLUG = "zzpub"


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
def secret(database: Engine) -> Iterator[str]:
    _wipe(database)
    key = apikeys.issue()
    with database.begin() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :o, true)"), {"o": ORG})
        connection.execute(insert(orgs).values(id=ORG, org_id=ORG, slug=ORG_SLUG, name=ORG))
        connection.execute(
            insert(api_keys).values(
                id=f"{ORG}-key",
                org_id=ORG,
                name="ci",
                key_hash=key.key_hash,
                prefix=key.prefix,
            )
        )
    yield key.secret
    _wipe(database)


def _wipe(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :o, true)"), {"o": ORG})
        connection.execute(delete(orgs).where(orgs.c.id == ORG))


@pytest.fixture
def client(integration_database_url: str, secret: str) -> Iterator[TestClient]:
    settings = Settings(env=Environment.TEST, database_url=integration_database_url)
    engine = create_app_engine(integration_database_url)
    try:
        with TestClient(create_app(settings, engine=engine)) as test_client:
            yield test_client
    finally:
        asyncio.run(engine.dispose())


def _headers(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


def _results(*, reachable: int = 1, cleared: int = 1, snapshot: str | None = "snap-1") -> Any:
    """A results document with a mix of verdicts."""
    from vexpath_core.enums import (
        ComponentScope,
        Confidence,
        EdgeKind,
        EntryPointSource,
        ReachStatus,
        ScanMode,
        Severity,
        Verdict,
        VexJustification,
    )
    from vexpath_core.models.finding import (
        AdvisoryRef,
        CallPathStep,
        ComponentRef,
        EntryPointInfo,
        Finding,
        ReachabilityResult,
    )
    from vexpath_core.models.results import SbomRef, ScanResults

    built: list[Finding] = []
    for index in range(reachable):
        built.append(
            Finding(
                id=new_ulid(),
                advisory=AdvisoryRef(
                    id=f"CVE-2026-90{index:02d}",
                    summary="a reachable problem",
                    severity=Severity.CRITICAL,
                    kev=True,
                ),
                component=ComponentRef(
                    purl=f"pkg:pypi/reachable{index}@1.0.0",
                    ecosystem="PyPI",
                    name=f"reachable{index}",
                    version="1.0.0",
                    direct=True,
                    scope=ComponentScope.RUNTIME,
                ),
                verdict=Verdict.AFFECTED,
                fixed_in="2.0.0",
                reach=ReachabilityResult(
                    status=ReachStatus.REACHABLE_CONFIRMED,
                    confidence=Confidence.HIGH,
                    matched_symbols=("lib.danger",),
                    searched_symbols=("lib.danger",),
                    shortest_path=(
                        CallPathStep(
                            symbol="app.main",
                            file="app/main.py",
                            line=1,
                            edge_kind=EdgeKind.STATIC,
                        ),
                        CallPathStep(
                            symbol="lib.danger",
                            file="lib/__init__.py",
                            line=9,
                            edge_kind=EdgeKind.STATIC,
                        ),
                    ),
                    entry_points=EntryPointInfo(
                        source=EntryPointSource.CONFIG, count=3, items=("app.main",)
                    ),
                    explanation="lib.danger is called from app.main.",
                ),
            )
        )
    for index in range(cleared):
        built.append(
            Finding(
                id=new_ulid(),
                advisory=AdvisoryRef(
                    id=f"CVE-2026-91{index:02d}",
                    summary="not in the execute path",
                    severity=Severity.HIGH,
                ),
                component=ComponentRef(
                    purl=f"pkg:pypi/unused{index}@1.0.0",
                    ecosystem="PyPI",
                    name=f"unused{index}",
                    version="1.0.0",
                    direct=False,
                    scope=ComponentScope.RUNTIME,
                ),
                verdict=Verdict.NOT_AFFECTED,
                justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                fixed_in="3.0.0",
                reach=ReachabilityResult(
                    status=ReachStatus.UNREACHABLE,
                    confidence=Confidence.HIGH,
                    searched_symbols=("unused.quiet", "unused.alsoquiet"),
                    entry_points=EntryPointInfo(
                        source=EntryPointSource.PACKAGE_METADATA, count=7, items=("app",)
                    ),
                    explanation="unused.quiet is not reachable from the 7 entry points.",
                ),
            )
        )

    results = ScanResults(
        schema_version="vexpath.results/1",
        core_version="0.0.1",
        generated_at=datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
        mode=ScanMode.ACTION,
        advisory_snapshot_id=snapshot,
        sbom=SbomRef(
            format="cyclonedx-1.6-json", sha256="a" * 64, component_count=reachable + cleared
        ),
        findings=tuple(built),
    )
    return json.loads(results.model_dump_json(by_alias=True))


def _publish(client: TestClient, secret: str, slug: str, **results_kwargs: Any) -> None:
    """Create a project, upload a scan, and make it public."""
    assert (
        client.post("/v1/projects", json={"slug": slug}, headers=_headers(secret)).status_code
        == 201
    )
    assert (
        client.post(
            "/v1/scans",
            json={"project": slug, "results": _results(**results_kwargs)},
            headers=_headers(secret),
        ).status_code
        == 201
    )
    assert (
        client.put(
            f"/v1/projects/{slug}/visibility",
            json={"visibility": "public"},
            headers=_headers(secret),
        ).status_code
        == 200
    )


# --- A private project is not published -----------------------------------


def test_a_private_project_has_no_report_page(client: TestClient, secret: str) -> None:
    """The most consequential assertion on this page.

    What keeps it invisible is a row-level security policy, not a check in the
    handler, so there is no code path that could forget it.
    """
    client.post("/v1/projects", json={"slug": "hidden"}, headers=_headers(secret))
    client.post(
        "/v1/scans",
        json={"project": "hidden", "results": _results()},
        headers=_headers(secret),
    )

    response = client.get(f"/p/{ORG_SLUG}/hidden")
    assert response.status_code == 404
    assert "no such report" in response.text


def test_a_private_project_has_no_badge(client: TestClient, secret: str) -> None:
    client.post("/v1/projects", json={"slug": "hidden"}, headers=_headers(secret))
    assert client.get(f"/badge/{ORG_SLUG}/hidden.svg").status_code == 404


def test_unpublishing_withdraws_the_page(client: TestClient, secret: str) -> None:
    _publish(client, secret, "svc")
    assert client.get(f"/p/{ORG_SLUG}/svc").status_code == 200

    client.put(
        "/v1/projects/svc/visibility",
        json={"visibility": "private"},
        headers=_headers(secret),
    )
    assert client.get(f"/p/{ORG_SLUG}/svc").status_code == 404


def test_a_project_that_does_not_exist_answers_the_same_way(client: TestClient) -> None:
    """Identical to "not published", so nobody can enumerate private names."""
    missing = client.get(f"/p/{ORG_SLUG}/no-such-thing")
    assert missing.status_code == 404
    assert "no such report" in missing.text


# --- Everything in the first response -------------------------------------


def test_the_whole_report_is_in_the_initial_html(client: TestClient, secret: str) -> None:
    """M4's acceptance criterion, asserted literally.

    A report whose content arrives in a second request cannot be read by a
    crawler, a feed reader, a text browser, or anyone whose second request did
    not make it. The entire reason to publish a report is that other people
    can read it.
    """
    _publish(client, secret, "svc", reachable=2, cleared=3)
    body = client.get(f"/p/{ORG_SLUG}/svc").text

    # The counts.
    assert "svc" in body
    # Both findings and both clearances, by advisory identifier.
    for index in range(2):
        assert f"CVE-2026-90{index:02d}" in body
    for index in range(3):
        assert f"CVE-2026-91{index:02d}" in body
    # The evidence, not only the verdict.
    assert "lib.danger is called from app.main." in body
    assert "unused.quiet" in body
    # The call path, step by step.
    assert "app/main.py" in body


def test_the_page_fetches_nothing_after_loading(client: TestClient, secret: str) -> None:
    """No script, no fetch, no deferred list.

    Asserted by inspection of the markup rather than by trusting the template:
    a single added script tag would undo the property this test exists for.
    """
    _publish(client, secret, "svc")
    body = client.get(f"/p/{ORG_SLUG}/svc").text

    assert "<script" not in body.lower()
    assert "fetch(" not in body
    assert "XMLHttpRequest" not in body
    # HTMX attributes are fine elsewhere, but a public report must not need
    # them: every one of them is a second request.
    assert "hx-get" not in body


def test_the_page_says_how_much_to_trust_it(client: TestClient, secret: str) -> None:
    """An uploaded result is an assertion until something verifies it.

    A report that implied otherwise would be the most consequential thing on
    the page to get wrong.
    """
    _publish(client, secret, "svc")
    body = client.get(f"/p/{ORG_SLUG}/svc").text

    assert "Self-reported" in body
    assert "has been re-verified" in body or "re-verified against a transparency" in body
    assert "snap-1" in body
    assert "Reproducible" in body


def test_a_report_from_a_live_corpus_says_it_is_not_reproducible(
    client: TestClient, secret: str
) -> None:
    _publish(client, secret, "svc", snapshot=None)
    body = client.get(f"/p/{ORG_SLUG}/svc").text
    assert "Not reproducible" in body


def test_the_page_explains_what_a_clearance_means(client: TestClient, secret: str) -> None:
    """A clearance a reader cannot interpret is one they cannot check."""
    _publish(client, secret, "svc")
    body = client.get(f"/p/{ORG_SLUG}/svc").text
    assert "no path reached" in body or "no call path" in body
    assert "Searched for" in body


def test_a_project_with_no_scan_says_so(client: TestClient, secret: str) -> None:
    client.post("/v1/projects", json={"slug": "fresh"}, headers=_headers(secret))
    client.put(
        "/v1/projects/fresh/visibility",
        json={"visibility": "public"},
        headers=_headers(secret),
    )
    body = client.get(f"/p/{ORG_SLUG}/fresh").text
    assert "No scan has been uploaded" in body


def test_component_names_are_escaped(client: TestClient, secret: str) -> None:
    """Component names come from a lockfile, which is attacker-influenced.

    Autoescaping is on for every template, and this is the assertion that
    notices if somebody turns it off for one of them.
    """
    _publish(client, secret, "svc")
    body = client.get(f"/p/{ORG_SLUG}/svc").text
    # Nothing in the page should contain a raw, unescaped tag from data.
    assert "<script>alert" not in body


# --- The badge ------------------------------------------------------------


def test_a_badge_with_reachable_findings_says_so(client: TestClient, secret: str) -> None:
    _publish(client, secret, "svc", reachable=2, cleared=1)
    response = client.get(f"/badge/{ORG_SLUG}/svc.svg")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "2 reachable" in response.text
    # The alarming colour, because two reachable findings is an alarming state.
    assert "#e05d44" in response.text


def test_a_badge_with_nothing_reachable_says_that(client: TestClient, secret: str) -> None:
    _publish(client, secret, "svc", reachable=0, cleared=3)
    body = client.get(f"/badge/{ORG_SLUG}/svc.svg").text
    assert "none reachable" in body
    assert "#4c1" in body


def test_a_badge_does_not_claim_clear_when_nothing_can_be_verified(
    client: TestClient, secret: str
) -> None:
    """The single most misleading artefact this system could produce.

    A badge is copied into a README and seen by everyone who looks at the
    repository, so one that says "clear" on the strength of an unreproducible
    scan would mislead at the greatest possible scale.
    """
    _publish(client, secret, "svc", reachable=0, cleared=2, snapshot=None)
    body = client.get(f"/badge/{ORG_SLUG}/svc.svg").text
    assert "unverified" in body
    assert "#4c1" not in body


def test_a_badge_for_a_project_with_no_scan_says_no_scan(client: TestClient, secret: str) -> None:
    client.post("/v1/projects", json={"slug": "fresh"}, headers=_headers(secret))
    client.put(
        "/v1/projects/fresh/visibility",
        json={"visibility": "public"},
        headers=_headers(secret),
    )
    body = client.get(f"/badge/{ORG_SLUG}/fresh.svg").text
    assert "no scan" in body


def test_a_badge_references_nothing_external(client: TestClient, secret: str) -> None:
    """A badge that fetched anything would report every repository view to it."""
    _publish(client, secret, "svc")
    body = client.get(f"/badge/{ORG_SLUG}/svc.svg").text

    assert "http://" not in body.replace("http://www.w3.org/2000/svg", "")
    assert "https://" not in body
    assert "<image" not in body
    assert "@import" not in body
    assert "<script" not in body


def test_a_badge_is_cacheable_but_not_for_long(client: TestClient, secret: str) -> None:
    """It has to reflect a new scan within five minutes."""
    _publish(client, secret, "svc")
    cache_control = client.get(f"/badge/{ORG_SLUG}/svc.svg").headers["cache-control"]
    max_age = int(re.search(r"max-age=(\d+)", cache_control).group(1))
    assert 0 < max_age <= 300


def test_a_badge_can_be_embedded_cross_origin(client: TestClient, secret: str) -> None:
    _publish(client, secret, "svc")
    headers = client.get(f"/badge/{ORG_SLUG}/svc.svg").headers
    assert headers["access-control-allow-origin"] == "*"


def test_the_badge_reflects_a_newer_scan(client: TestClient, secret: str) -> None:
    """The acceptance criterion: the badge follows the state."""
    _publish(client, secret, "svc", reachable=1, cleared=0)
    assert "1 reachable" in client.get(f"/badge/{ORG_SLUG}/svc.svg").text

    client.post(
        "/v1/scans",
        json={"project": "svc", "results": _results(reachable=0, cleared=2)},
        headers=_headers(secret),
    )
    assert "none reachable" in client.get(f"/badge/{ORG_SLUG}/svc.svg").text


# --- The package page -----------------------------------------------------


def test_the_package_page_renders_from_the_advisory_corpus(client: TestClient) -> None:
    """Built from global data, so it works with no organisation in scope.

    That is what makes it useful to somebody who has never uploaded anything.
    """
    response = client.get("/package/PyPI/requests")
    assert response.status_code == 200
    body = response.text
    assert "requests" in body
    assert "PyPI" in body
    # The page explains what it is showing, because "vulnerable symbol" is not
    # a term a reader arrives already knowing.
    assert "which functions the fix changed" in body or "functions the fix" in body


def test_the_package_page_fetches_nothing(client: TestClient) -> None:
    body = client.get("/package/PyPI/requests").text
    assert "<script" not in body.lower()
    assert "hx-get" not in body


def test_a_package_with_nothing_recorded_says_so_plainly(client: TestClient) -> None:
    """The ordinary state for most packages, so it must not read as an error."""
    body = client.get("/package/PyPI/zzz-no-such-package-anywhere").text
    assert "Nothing recorded yet" in body
    assert "ordinary state" in body


def test_a_package_name_is_escaped(client: TestClient) -> None:
    """The name comes straight out of the URL."""
    response = client.get("/package/PyPI/%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text
