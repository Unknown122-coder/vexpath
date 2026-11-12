"""Fixtures shared by every package's tests.

Lives at the repository root because the fixture data it points at is shared:
one frozen advisory snapshot and one set of fixture repositories, used by the
core tests, the database tests and the benchmark alike.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vexpath_platform.eventloop import configure_event_loop

# Colour off, before anything imports rich or typer. Those libraries decide
# at import time whether to emit escape codes, and they honour FORCE_COLOR
# from the surrounding environment -- so a suite that asserts on the text of
# a CLI message passes or fails according to the terminal that happened to
# start it. Six tests failed exactly that way, with FORCE_COLOR=3 inherited
# from an editor's integrated shell, in a session where nothing about the
# code had changed.
os.environ.pop("FORCE_COLOR", None)
os.environ.setdefault("NO_COLOR", "1")
os.environ.setdefault("TERM", "dumb")

# Windows defaults to an event loop psycopg's asynchronous mode cannot use, so
# every asynchronous database test would fail with an interface error naming
# the loop and not the remedy. Set once, at collection, for the whole run.
configure_event_loop()

REPO_ROOT = Path(__file__).parent
TESTDATA = REPO_ROOT / "testdata"

#: A fixed instant, used wherever a test needs a clock. Keeping it in one place
#: means a test that prints a timestamp prints the same one on every machine.
FROZEN_NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="session")
def testdata_dir() -> Path:
    """Root of the committed test data."""
    return TESTDATA


@pytest.fixture(scope="session")
def snapshot_dir(testdata_dir: Path) -> Path:
    """The frozen advisory snapshot directory."""
    return testdata_dir / "advisories"


@pytest.fixture(scope="session")
def sboms_dir(testdata_dir: Path) -> Path:
    """Fixture SBOM documents."""
    return testdata_dir / "sboms"


@pytest.fixture(scope="session")
def fixture_repos_dir(testdata_dir: Path) -> Path:
    """Fixture repositories used by the reachability tests and benchmark."""
    return testdata_dir / "repos"


@pytest.fixture
def frozen_clock() -> object:
    """A clock stuck at :data:`FROZEN_NOW`."""
    from vexpath_core.protocols import FixedClock

    return FixedClock(FROZEN_NOW)


#: How long to wait for the integration database before giving up on it.
#:
#: Short on purpose. This is the "is it even there" probe, not a query: a
#: developer who has not started the stack should be told so in two seconds.
_PROBE_TIMEOUT = 2


@pytest.fixture(scope="session")
def _integration_database() -> str:
    """Check once per session that Postgres is reachable, or skip everything.

    Each test used to find this out for itself, which was fine until the
    connection had a timeout: with the stack down, a suite of integration
    tests spent that timeout per test and took tens of minutes to report
    nothing. Probing once per session costs two seconds and then every
    integration test skips immediately.

    Session-scoped, so the cost is paid once however many tests ask for it.
    """
    from sqlalchemy import text

    from vexpath_db.engine import create_sync_engine

    url = os.environ.get(
        "VEXPATH_TEST_DATABASE_URL",
        "postgresql+psycopg://vexpath:vexpath@localhost:5432/vexpath",
    )
    engine = create_sync_engine(url, connect_timeout=_PROBE_TIMEOUT)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - any failure means "not available"
        pytest.skip(
            f"no integration database at {url.rsplit('@', 1)[-1]} "
            f"({type(exc).__name__}). Start it with 'make up'."
        )
    finally:
        engine.dispose()
    return url


@pytest.fixture
def integration_database_url(_integration_database: str) -> str:
    """Connection string for tests that need a real Postgres.

    Defaults to the docker compose database so that ``make up && make test-all``
    works with no further setup. Skips, rather than fails, when there is no
    database to talk to -- see :func:`_integration_database`.
    """
    return _integration_database


@pytest.fixture
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove ``VEXPATH_`` variables so a developer's .env cannot change a result.

    Without this, a test asserting a default would pass or fail depending on
    what happens to be exported in the shell that ran it.
    """
    for name in list(os.environ):
        if name.startswith("VEXPATH_"):
            monkeypatch.delenv(name, raising=False)
    yield
