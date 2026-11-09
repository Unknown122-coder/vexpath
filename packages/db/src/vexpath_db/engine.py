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


def create_sync_engine(
    url: str, *, echo: bool = False, connect_timeout: int | None = None
) -> Engine:
    """Create a synchronous engine, for Alembic, workers and scripts.

    Args:
        connect_timeout: Seconds to wait for a connection. Worth setting in
            scripts and tests, where waiting on a database that is simply not
            running should fail quickly rather than appear to hang.
    """
    connect_args = {"connect_timeout": connect_timeout} if connect_timeout else {}
    return create_engine(
        normalise_url(url, async_=False),
        echo=echo,
        pool_pre_ping=True,
        future=True,
        connect_args=connect_args,
    )


def create_app_engine(url: str, *, echo: bool = False) -> AsyncEngine:
    """Create an asynchronous engine, for the API process."""
    return create_async_engine(
        normalise_url(url, async_=True),
        echo=echo,
        pool_pre_ping=True,
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
