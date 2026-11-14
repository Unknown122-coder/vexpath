"""A real server, a real browser, and the fixtures that make them optional.

These tests drive a live uvicorn process with Chromium. That is worth doing
for exactly one reason: everything else in this suite asserts what a handler
*returns*, and the claim this product makes about its interface is about what a
browser can *do* with it. A page can return perfect HTML and still be unusable
if the form posts to the wrong place.

**They skip rather than fail when the browser is absent.** `playwright` is a
development dependency and its browser is a separate 150 MB download; a suite
that could not run without it would be a suite most people never run. The skip
message says exactly what to install.

**The server runs in its own process**, and that is forced rather than
chosen. psycopg's asynchronous mode needs a selector event loop on Windows;
Playwright's synchronous API starts its driver with
``asyncio.create_subprocess_exec``, which a selector loop does not implement.
One process cannot satisfy both and the policy is process-wide, so the server
gets the selector policy it needs and this process keeps the proactor policy
Playwright needs. ``run_server.py`` holds the other half, including the fake
identity provider — which lives in test code rather than behind a setting,
because a deployment must have no way to swap its sign-in for a stand-in.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from sqlalchemy import delete, select, text

from vexpath_db.engine import create_sync_engine
from vexpath_db.tables import orgs

if TYPE_CHECKING:
    from sqlalchemy import Engine

#: Both markers. ``e2e`` is deselected by default (see the addopts in
#: pyproject.toml) because this suite cannot share a process with the
#: asynchronous database tests: Playwright needs the proactor event loop
#: and psycopg needs the selector one, and the policy is process-wide.
pytestmark = [pytest.mark.integration, pytest.mark.e2e]

#: The account these tests sign in as. Defined in ``run_server.py``; the slug
#: is what the organisation gets from the login.
ORG_SLUG = "acceptance"
SECRET_KEY = "a-process-secret-for-the-acceptance-tests"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip this suite rather than corrupt the process it was collected into.

    The constraint above was written down and still broken twice, because
    nothing enforced it: a ``-m`` on the command line replaces the ``-m 'not
    e2e'`` in addopts, so any selector that forgets to repeat it collects
    these tests alongside the asynchronous database tests. The
    :func:`browser` fixture then installs the proactor policy for the rest of
    the session and every psycopg test after it fails -- far from here, in
    tests that pass when run on their own, which is the worst possible place
    for the symptom to appear.

    So when the session holds anything that is not an e2e test, the e2e tests
    skip and say what to run instead. A suite that runs alone -- ``make e2e``,
    where everything collected is e2e -- is untouched.
    """
    del config
    e2e = [item for item in items if item.get_closest_marker("e2e") is not None]
    if not e2e or len(e2e) == len(items):
        return

    skip = pytest.mark.skip(
        reason=(
            "the acceptance suite needs its own process (Playwright wants the "
            "proactor event loop, psycopg the selector one) and this session "
            "also collected other tests; run 'make e2e'"
        )
    )
    for item in e2e:
        item.add_marker(skip)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@pytest.fixture(scope="session")
def browser() -> Iterator[Any]:
    """A Chromium instance, or a skip explaining what to install.

    Restores the proactor event-loop policy for the duration, because
    Playwright starts its driver as a subprocess and a selector loop cannot do
    that. Nothing in this process talks to Postgres asynchronously -- the
    server is a separate process and the fixtures here use the synchronous
    engine -- so taking the policy back is safe, and the alternative is a
    ``NotImplementedError`` from deep inside asyncio that explains nothing.
    """
    playwright = pytest.importorskip(
        "playwright.sync_api",
        reason="playwright is not installed: uv sync --dev",
    )
    saved = asyncio.get_event_loop_policy()
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    try:
        yield from _launch(playwright)
    finally:
        asyncio.set_event_loop_policy(saved)


def _launch(playwright: Any) -> Iterator[Any]:
    with playwright.sync_playwright() as driver:
        try:
            instance = driver.chromium.launch()
        except Exception as exc:  # noqa: BLE001 - a missing browser skips, not fails
            pytest.skip(f"chromium is not installed: uv run playwright install chromium ({exc})")
        try:
            yield instance
        finally:
            instance.close()


@dataclass
class Server:
    """Where the live application is listening."""

    base_url: str
    org_slug: str = ORG_SLUG


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
        for row in connection.execute(select(orgs.c.id).where(orgs.c.slug == ORG_SLUG)).all():
            connection.execute(
                text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": row.id}
            )
            connection.execute(delete(orgs).where(orgs.c.id == row.id))


@pytest.fixture
def server(integration_database_url: str, database: Engine, tmp_path: Path) -> Iterator[Server]:
    """A live application on a free port, in its own process.

    Its output goes to a file rather than a pipe. A pipe nobody reads fills and
    then blocks the child mid-request, which would look like the server
    hanging; and an unread pipe left open is a resource warning, which this
    suite treats as a failure. The file is read when something goes wrong,
    which is when it is worth having.

    Readiness is polled through the application's own liveness probe rather
    than slept for: a sleep long enough on a fast machine is not long enough on
    a busy one, and a test that fails for that reason gets rerun rather than
    fixed.
    """
    port = _free_port()
    runner = Path(__file__).with_name("run_server.py")
    log = tmp_path / "server.log"
    sink = log.open("wb")
    process = subprocess.Popen(
        [
            sys.executable,
            str(runner),
            "--port",
            str(port),
            "--database-url",
            integration_database_url,
            "--secret-key",
            SECRET_KEY,
        ],
        cwd=str(Path(__file__).resolve().parents[4]),
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        stdout=sink,
        stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_ready(process, base_url, log)
        yield Server(base_url=base_url)
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)
        sink.close()


def _wait_until_ready(process: subprocess.Popen[bytes], base_url: str, log: Path) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(
                "the application exited before serving:\n"
                + log.read_text(encoding="utf-8", errors="replace")
            )
        try:
            if httpx.get(f"{base_url}/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.1)
    process.terminate()
    pytest.fail("the application did not become ready")


@pytest.fixture
def page(browser: Any, server: Server) -> Iterator[Any]:
    """A browser page with JavaScript enabled."""
    context = browser.new_context(base_url=server.base_url)
    try:
        yield context.new_page()
    finally:
        context.close()


@pytest.fixture
def scripted_out(browser: Any, server: Server) -> Iterator[Any]:
    """A browser page with JavaScript **disabled**.

    The acceptance criterion for this interface, and the reason it is a
    fixture rather than a flag on one test: every page worth having is worth
    having without script. ADR-0011 chose server-rendered HTML with HTMX
    attributes precisely so that this context sees a working application
    rather than a blank shell.
    """
    context = browser.new_context(base_url=server.base_url, java_script_enabled=False)
    try:
        yield context.new_page()
    finally:
        context.close()


def results_document() -> dict[str, Any]:
    """A scan result with one reachable finding and a real call path.

    Built through the models the analysis produces rather than written out, so
    a schema change breaks this at the point of construction instead of
    surfacing as a 422 that looks like an upload problem. The path is what the
    finding page is asserted to render, hop by hop.
    """
    import json
    from datetime import UTC, datetime

    from vexpath_core.enums import (
        ComponentScope,
        Confidence,
        EdgeKind,
        EntryPointSource,
        ReachStatus,
        ScanMode,
        Severity,
        Verdict,
    )
    from vexpath_core.models.finding import (
        AdvisoryRef,
        CallPathStep,
        ComponentRef,
        EntryPointInfo,
        Finding,
        GraphStats,
        ReachabilityResult,
    )
    from vexpath_core.models.results import SbomRef, ScanResults

    finding = Finding(
        id="01JACCEPTANCE000000000000",
        advisory=AdvisoryRef(id="CVE-2026-0001", severity=Severity.HIGH, kev=True),
        component=ComponentRef(
            purl="pkg:pypi/jinja2@3.1.0",
            ecosystem="PyPI",
            name="jinja2",
            version="3.1.0",
            direct=True,
            scope=ComponentScope.RUNTIME,
        ),
        verdict=Verdict.AFFECTED,
        reach=ReachabilityResult(
            status=ReachStatus.REACHABLE_CONFIRMED,
            confidence=Confidence.HIGH,
            matched_symbols=("jinja2.sandbox.unsafe",),
            searched_symbols=("jinja2.sandbox.unsafe",),
            shortest_path=(
                CallPathStep(symbol="app.main:handler", file="app/main.py", line=11),
                CallPathStep(
                    symbol="jinja2.sandbox.unsafe",
                    file="jinja2/sandbox.py",
                    line=402,
                    edge_kind=EdgeKind.STATIC,
                ),
            ),
            path_count=1,
            entry_points=EntryPointInfo(
                source=EntryPointSource.CONFIG,
                count=1,
                items=("app.main:handler",),
            ),
            graph_stats=GraphStats(
                first_party_nodes=120, first_party_edges=310, unresolved_call_ratio=0.1
            ),
            explanation="reached from app.main:handler",
        ),
        fixed_in="3.1.3",
    )
    results = ScanResults(
        schema_version="vexpath.results/1",
        core_version="0.0.1",
        generated_at=datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
        mode=ScanMode.CLI,
        advisory_snapshot_id="snap-acceptance",
        sbom=SbomRef(format="cyclonedx-1.6-json", sha256="a" * 64, component_count=1),
        findings=(finding,),
    )
    document: dict[str, Any] = json.loads(results.model_dump_json(by_alias=True))
    return document


def sign_in(page: Any) -> None:
    """Complete the sign-in flow by clicking through it.

    Clicked rather than driven by URL: a link whose href is wrong is a bug
    this test should catch, and following it by hand would hide exactly that.

    Addressed by role and exact name, like every control in these tests.
    Playwright's ``text=`` selector matches *substrings*, which is a trap worth
    naming: a button called "Publish" is also matched by a project named
    "published", and "Save" is matched by the sentence "Saving stores the
    expression". Both of those happened here, and both looked like the
    interface being broken rather than the test.
    """
    page.goto("/login")
    page.get_by_role("link", name="Continue with GitHub", exact=True).click()
    page.wait_for_url("**/app")


__all__ = ["ORG_SLUG", "SECRET_KEY", "Server", "results_document", "sign_in"]
