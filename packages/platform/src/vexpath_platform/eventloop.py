"""Choose an event loop psycopg can actually use.

Windows defaults to the proactor event loop, and psycopg's asynchronous mode
cannot run on it: every connection fails with an interface error that names the
loop but not what to do about it. The selector loop works.

This lives in the platform package rather than in a test fixture because it is
not a test problem. A developer running the API on Windows hits it on their
first request, and so would a Windows container. Fixing it in one place that
both the process entry point and the tests call is what stops it being
rediscovered.

**Setting the policy is not enough under uvicorn, and that cost a real
afternoon.** Since 0.36 uvicorn builds its loop from its own factory and
ignores the installed policy; on Windows that factory hardcodes the proactor
loop. So ``uvicorn vexpath_api.main:app`` cannot reach the database on Windows
however the policy is set — every query answers with an interface error and
``/readyz`` reports the database down while the process looks healthy. The
remedy is to hand uvicorn a factory of our own:

    uvicorn vexpath_api.main:app --loop vexpath_platform.eventloop:event_loop_factory

That flag is in the Makefile, the Dockerfile and the compose file, and
``UVICORN_LOOP_FACTORY`` below is the string to use so none of them can drift
from the others. It is harmless everywhere else: off Windows this returns the
same loop asyncio would have chosen.

``configure_event_loop`` remains the right call for anything that runs
``asyncio.run`` itself — the worker, and the tests.
"""

from __future__ import annotations

import asyncio
import os

#: What to pass to ``uvicorn --loop``. One string, so the Makefile, the
#: Dockerfile and the compose file cannot disagree about it.
UVICORN_LOOP_FACTORY = "vexpath_platform.eventloop:event_loop_factory"


def event_loop_factory() -> asyncio.AbstractEventLoop:
    """A new event loop the database driver can use.

    Shaped for ``uvicorn --loop <import string>``, which expects a zero-argument
    callable returning a loop. On Windows that is deliberately *not* the
    proactor loop uvicorn would otherwise pick; everywhere else it is the
    ordinary one.
    """
    # ``os.name`` rather than ``sys.platform``: a type checker special-cases
    # the latter, narrows it to whichever platform the check is running on,
    # and then calls the other branch dead code -- which is exactly the branch
    # that matters on the other platform.
    if os.name == "nt":
        return asyncio.SelectorEventLoop()
    return asyncio.new_event_loop()


def configure_event_loop() -> bool:
    """Install an event loop policy the database driver can use.

    For code that creates its own loop through ``asyncio.run`` or
    ``asyncio.get_event_loop``: the worker, the command line, and the tests.
    It does **not** affect uvicorn, which builds its own loop — see the module
    docstring and ``UVICORN_LOOP_FACTORY``.

    Returns:
        True when the policy was changed, which is only ever on Windows. The
        return value exists so a caller can log it: a changed policy is the
        kind of thing that is useful to see in a startup line when something
        later goes wrong with connections.
    """
    # os.name, not sys.platform: a type checker special-cases the latter and
    # narrows it to whichever platform it is running on, so one of the two
    # branches is reported as dead code -- and which one depends on where the
    # check runs. This failed on Linux after passing on Windows.
    if os.name != "nt":
        return False

    policy = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
    if policy is None:  # pragma: no cover - only on a Python without it
        return False
    if isinstance(asyncio.get_event_loop_policy(), policy):
        return False

    asyncio.set_event_loop_policy(policy())
    return True


__all__ = ["UVICORN_LOOP_FACTORY", "configure_event_loop", "event_loop_factory"]
