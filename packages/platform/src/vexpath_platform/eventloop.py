"""Choose an event loop psycopg can actually use.

Windows defaults to the proactor event loop, and psycopg's asynchronous mode
cannot run on it: every connection fails with an interface error that names the
loop but not what to do about it. The selector loop works.

This lives in the platform package rather than in a test fixture because it is
not a test problem. A developer running the API on Windows hits it on their
first request, and so would a Windows container. Fixing it in one place that
both the process entry point and the tests call is what stops it being
rediscovered.

Called at process start, never from ``create_app``: replacing the global event
loop policy is a process-wide decision, and a library function that did it as a
side effect would surprise anything else running in the same interpreter.
"""

from __future__ import annotations

import asyncio
import sys


def configure_event_loop() -> bool:
    """Install an event loop policy the database driver can use.

    Returns:
        True when the policy was changed, which is only ever on Windows. The
        return value exists so a caller can log it: a changed policy is the
        kind of thing that is useful to see in a startup line when something
        later goes wrong with connections.
    """
    if sys.platform != "win32":
        return False

    policy = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
    if policy is None:  # pragma: no cover - only on a Python without it
        return False
    if isinstance(asyncio.get_event_loop_policy(), policy):
        return False

    asyncio.set_event_loop_policy(policy())
    return True


__all__ = ["configure_event_loop"]
