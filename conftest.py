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


@pytest.fixture
def integration_database_url() -> str:
    """Connection string for tests that need a real Postgres.

    Defaults to the docker compose database so that ``make up && make test-all``
    works with no further setup.
    """
    return os.environ.get(
        "VEXPATH_TEST_DATABASE_URL",
        "postgresql+psycopg://vexpath:vexpath@localhost:5432/vexpath",
    )


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
