"""The engine factories, and the wait they are not allowed to make.

libpq waits for a connection indefinitely unless a ``connect_timeout`` says
otherwise, and "indefinitely" is not an abstraction here: with no timeout set,
this project's own readiness test took 130 seconds to report a database that
was not there, holding a worker for the whole of it. Fly asks ``/readyz``
every fifteen seconds, so that is a queue of stuck requests on the single
machine that is meant to be serving.

The symptom was a slow test, which reads as an annoyance rather than as a
production defect. Hence this file.
"""

from __future__ import annotations

import inspect
import socket
import time
from collections.abc import Iterator

import pytest
from sqlalchemy.exc import OperationalError

from vexpath_db.engine import (
    CONNECT_TIMEOUT_SECONDS,
    create_app_engine,
    create_sync_engine,
    normalise_url,
)


@pytest.mark.parametrize("factory", [create_sync_engine, create_app_engine])
def test_every_engine_bounds_the_wait_by_default(factory: object) -> None:
    """Opt-out, not opt-in.

    The timeout existed before as a parameter defaulting to ``None``, which
    meant every caller that did not think about it got the unbounded wait --
    and none of the five call sites in the worker thought about it.
    """
    default = inspect.signature(factory).parameters["connect_timeout"].default  # type: ignore[arg-type]
    assert default == CONNECT_TIMEOUT_SECONDS


def test_the_timeout_is_long_enough_for_a_sleeping_database() -> None:
    # Neon suspends its compute when idle and the connection that wakes it is
    # the slow one. A probe should give up in seconds; real work should not.
    assert 5 <= CONNECT_TIMEOUT_SECONDS <= 30


@pytest.fixture
def silent_server() -> Iterator[int]:
    """A listener that accepts a connection and then says nothing.

    A refused connection proves nothing: the operating system answers that
    immediately whatever libpq is configured to do. The failure that hangs is
    a server that accepts and never speaks, which is also what a packet
    filter dropping traffic looks like from here.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()


def test_the_timeout_reaches_libpq(silent_server: int) -> None:
    """Set two seconds, wait about two seconds, not for ever.

    Checked by behaviour rather than by reading the keyword back off the
    engine, because SQLAlchemy keeps ``connect_args`` in a closure: an
    assertion about where it is stored would pass while the value went
    nowhere.
    """
    engine = create_sync_engine(
        f"postgresql://nobody@127.0.0.1:{silent_server}/none", connect_timeout=2
    )
    started = time.monotonic()
    with pytest.raises(OperationalError), engine.connect():
        pass
    elapsed = time.monotonic() - started
    assert elapsed < 15, f"the timeout did not reach libpq: waited {elapsed:.0f}s"


def test_the_url_is_rewritten_to_this_project_s_drivers() -> None:
    # A connection string pasted from Neon or Fly should just work.
    assert normalise_url("postgres://u@h/db", async_=False).startswith("postgresql+psycopg://")
    assert normalise_url("postgresql://u@h/db", async_=True).startswith("postgresql+psycopg://")
    with pytest.raises(ValueError, match="not a database URL"):
        normalise_url("nonsense", async_=False)
