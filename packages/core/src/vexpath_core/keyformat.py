"""The shape of an API key, as both ends of the wire understand it.

This is here, in the shared package, rather than with the rest of the API key
handling in ``vexpath_platform``, and the reason is a packaging one worth
recording: the command-line tool needs to recognise a key and show a safe
prefix of one, and it must not depend on the *server* package to do it. A
published ``vexpath`` wheel that pulled in the platform would install the
server's settings, logging and request machinery onto a laptop, and a future
server dependency -- a database driver, say -- would silently land there too.

Duplicating the prefix in two packages was the alternative, and this is
better: the prefix is the public wire format, a secret scanner matches on it,
and two definitions of it would eventually disagree.

Issuing, hashing and verifying a key stay in ``vexpath_platform``, because
those are things only the server does.
"""

from __future__ import annotations

#: Prefix on every live key. Fixed and recognisable so secret scanners can
#: match it, which is what gets a leaked key revoked before it is used.
KEY_PREFIX = "vexpath_live_"

#: How much of the key is shown in the clear, so a dashboard or the command
#: line can tell two keys apart. Short enough that it narrows nothing: the
#: remainder is still 256 bits of search space.
VISIBLE_SUFFIX = 6


def looks_like_key(value: str) -> bool:
    """Whether a string is shaped like one of our keys.

    Used to decide whether to attempt a lookup at all, and to catch a typo
    before it becomes an authentication failure on some later command. Never
    to decide whether a key is *valid*: rejecting an obviously wrong shape
    saves a round trip, and it must never be the reason a real key is
    refused.
    """
    candidate = value.strip()
    return candidate.startswith(KEY_PREFIX) and len(candidate) > len(KEY_PREFIX) + 10


def display_prefix(secret: str) -> str:
    """What is safe to print beside a key.

    The fixed prefix plus a few characters of the secret: enough to tell two
    keys apart, not enough to help anyone guess one. Everything that would
    otherwise be tempted to slice the secret itself calls this, so the
    boundary is decided once.
    """
    token = secret.strip().removeprefix(KEY_PREFIX)
    return f"{KEY_PREFIX}{token[:VISIBLE_SUFFIX]}"


__all__ = ["KEY_PREFIX", "VISIBLE_SUFFIX", "display_prefix", "looks_like_key"]
