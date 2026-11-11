"""Engine and session construction.

One driver, psycopg version 3, serves both synchronous and asynchronous access.
Callers pass a single URL and get the right engine for the context, so there is
no second connection string to keep in step.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

_ASYNC_DRIVER = "postgresql+psycopg"
_SYNC_DRIVER = "postgresql+psycopg"


def normalise_url(url: str, *, async_: bool) -> str:
    """Return ``url`` with the driver this project uses.

    Accepts the shapes people actually paste: a bare ``postgres://`` or
    ``postgresql://`` URL from a hosting provider, or one that already names a
    driver. The driver is rewritten rather than rejected, because a connection
    string copied from Neon or Fly should just work.
    """
    _, _, remainder = url.partition("://")
    if not remainder:
        msg = f"not a database URL: {url!r}"
        raise ValueError(msg)
    driver = _ASYNC_DRIVER if async_ else _SYNC_DRIVER
    return f"{driver}://{remainder}"


#: Seconds to wait for a connection before giving up.
#:
#: libpq waits indefinitely by default, and indefinitely is what it did: a
#: connection to an address nothing was listening on took **130 seconds** to
#: fail in this project's own test suite. That number is invisible until it
#: matters, and where it matters is ``/readyz``, which holds a worker for as
#: long as the attempt takes. A readiness probe that hangs is worse than one
#: that says no -- the orchestrator learns nothing and the process is busy.
#:
#: Ten seconds, not five, because Neon suspends its compute when idle and the
#: connection that wakes it is the slow one. The tight bound belongs on the
#: readiness probe, which should answer "not yet" in three seconds and be
#: asked again, not on real work that ought to wait for a database that is
#: merely asleep.
CONNECT_TIMEOUT_SECONDS = 10


def create_sync_engine(
    url: str, *, echo: bool = False, connect_timeout: int | None = CONNECT_TIMEOUT_SECONDS
) -> Engine:
    """Create a synchronous engine, for Alembic, workers and scripts.

    Args:
        connect_timeout: Seconds to wait for a connection, defaulting to
            :data:`CONNECT_TIMEOUT_SECONDS`. This is where the old default of
            "wait for ever" did the most damage: a scheduled worker machine
            pointed at a database that is not there does not fail, it sits,
            and on a host that bills by the machine-second it sits until
            somebody notices. ``None`` restores the wait.
    """
    connect_args = {"connect_timeout": connect_timeout} if connect_timeout else {}
    return create_engine(
        normalise_url(url, async_=False),
        echo=echo,
        pool_pre_ping=True,
        future=True,
        connect_args=connect_args,
    )


def create_app_engine(
    url: str, *, echo: bool = False, connect_timeout: int | None = CONNECT_TIMEOUT_SECONDS
) -> AsyncEngine:
    """Create an asynchronous engine, for the API process.

    Args:
        connect_timeout: Seconds to wait for a connection. Defaults to
            :data:`CONNECT_TIMEOUT_SECONDS` rather than to libpq's "wait for
            ever", for the reason given there. ``None`` restores the wait.
    """
    return create_async_engine(
        normalise_url(url, async_=True),
        echo=echo,
        pool_pre_ping=True,
        connect_args={"connect_timeout": connect_timeout} if connect_timeout else {},
        # The reference deployment runs on small free-tier instances against a
        # connection-limited Postgres, so the pool stays deliberately narrow.
        pool_size=5,
        max_overflow=5,
    )


@contextmanager
def sync_connection(engine: Engine) -> Iterator[Connection]:
    """A transactional synchronous connection."""
    with engine.begin() as connection:
        yield connection


@asynccontextmanager
async def async_connection(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """A transactional asynchronous connection."""
    async with engine.begin() as connection:
        yield connection


__all__ = [
    "async_connection",
    "create_app_engine",
    "create_sync_engine",
    "normalise_url",
    "sync_connection",
]
