"""Rate limiting.

What this defends against, stated plainly, because a limiter sold as
protection it does not provide is worse than none.

It does **not** defend an API key against guessing. A key is 256 bits from the
system random source; there is no rate at which guessing it becomes feasible,
and a limiter that implied otherwise would invite somebody to shorten the key.
What it defends against is a misconfigured CI job retrying in a tight loop, a
scraper walking the public report pages, and the cost of either — all of which
are ordinary and none of which involve an attacker.

Three decisions follow.

**The window is fixed, not a token bucket.** A fixed window is less smooth and
far easier to reason about, and the thing a person needs from a limiter is to
be able to say what it will do. `Retry-After` is then the honest number of
seconds until the window turns over, rather than an estimate.

**The table of counters is bounded.** An unbounded dictionary keyed by client
address is a memory-exhaustion vector: anybody who can vary the key can grow
it without limit. The map is capped and the oldest entries are discarded when
it fills, which degrades into "not limiting that client" rather than into "the
process dies".

**It never keys on a secret.** An API key is identified by a short prefix of
its hash, never by the key: a limiter whose state can be dumped must not be a
place credentials are kept.

The state is per process, and that is a real limitation rather than an
oversight: two instances behind a load balancer each allow the configured rate.
It is written down here because the alternative — a shared counter in Postgres
— costs a write on every request, and that trade is worth revisiting only when
there is more than one instance.
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from dataclasses import dataclass

#: How many distinct clients are tracked at once. Beyond this the oldest entry
#: is discarded: the limiter forgets somebody rather than the process running
#: out of memory, because an unbounded map keyed by a value the caller chooses
#: is a denial of service with extra steps.
MAX_TRACKED = 20_000


@dataclass(frozen=True, slots=True)
class Rule:
    """How many requests are allowed in how long.

    Expressed as a pair rather than a rate, so the answer to "how many can I
    send right now" is a number somebody can read off the configuration.
    """

    limit: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.limit < 1 or self.window_seconds < 1:
            msg = "a rate limit rule needs a positive limit and window"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class Decision:
    """Whether a request may proceed, and what to tell the caller."""

    allowed: bool
    remaining: int
    #: Seconds until the window turns over. Sent as ``Retry-After``, so it has
    #: to be a real number of seconds rather than a guess: a client that obeys
    #: a wrong one either hammers or stalls.
    retry_after: int
    limit: int


class Limiter:
    """Fixed-window counters, bounded in number.

    One instance per process, consulted by the middleware. Not thread-safe by
    construction and does not need to be: the server runs one event loop, and
    an ``await`` never happens inside ``check``.
    """

    def __init__(self, *, max_tracked: int = MAX_TRACKED) -> None:
        # Insertion-ordered, so discarding the oldest is O(1) and the eviction
        # policy is visible rather than emergent.
        self._windows: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._max_tracked = max_tracked

    def check(self, key: str, rule: Rule, *, now: float | None = None) -> Decision:
        """Count one request against a rule.

        Counts it whether or not it is allowed, deliberately: a client that
        keeps sending during a refusal stays refused for the rest of the
        window instead of discovering that rejected requests are free.
        """
        moment = time.monotonic() if now is None else now
        window_start = int(moment // rule.window_seconds) * rule.window_seconds
        retry_after = max(1, int(window_start + rule.window_seconds - moment))

        existing = self._windows.get(key)
        # A new window resets the count. Written as a conditional expression
        # because the two branches are one decision -- is this the same window
        # -- rather than two things happening.
        count = 1 if existing is None or existing[0] != window_start else existing[1] + 1

        self._windows[key] = (window_start, count)
        self._windows.move_to_end(key)
        while len(self._windows) > self._max_tracked:
            # Forget somebody rather than grow without bound. The consequence
            # is that one client stops being limited, which is strictly better
            # than the process dying.
            self._windows.popitem(last=False)

        return Decision(
            allowed=count <= rule.limit,
            remaining=max(0, rule.limit - count),
            retry_after=retry_after,
            limit=rule.limit,
        )

    def reset(self) -> None:
        """Forget every counter. For tests, and for nothing else."""
        self._windows.clear()

    @property
    def tracked(self) -> int:
        return len(self._windows)


def identity_from_key(secret: str) -> str:
    """A stable identifier for an API key that is not the key.

    The first sixteen hex characters of its SHA-256: enough to separate
    callers, useless to anybody who reads it. A limiter whose state can be
    dumped in a heap profile must not be a place credentials are kept.
    """
    return hashlib.sha256(secret.strip().encode("utf-8")).hexdigest()[:16]


__all__ = ["MAX_TRACKED", "Decision", "Limiter", "Rule", "identity_from_key"]
