"""The rate limiter.

Three properties, in order of how badly they fail when wrong.

**The counter table is bounded.** An unbounded map keyed by a value the caller
chooses is a denial of service with extra steps, and it is the most common way
a hand-written limiter becomes the vulnerability it was added to prevent.

**A refused request still counts.** Otherwise a client that keeps sending
during a refusal discovers that rejected requests are free, and the limiter
stops limiting precisely when it is needed.

**``Retry-After`` is a real number of seconds.** A client that obeys a wrong
one either hammers or stalls, and both look like the limiter misbehaving.
"""

from __future__ import annotations

import pytest

from vexpath_platform.ratelimit import Limiter, Rule, identity_from_key


def test_requests_under_the_limit_are_allowed() -> None:
    limiter = Limiter()
    rule = Rule(limit=3, window_seconds=60)
    assert [limiter.check("a", rule, now=0.0).allowed for _ in range(3)] == [True] * 3


def test_the_request_over_the_limit_is_refused() -> None:
    limiter = Limiter()
    rule = Rule(limit=2, window_seconds=60)
    limiter.check("a", rule, now=0.0)
    limiter.check("a", rule, now=0.0)
    assert limiter.check("a", rule, now=0.0).allowed is False


def test_a_refused_request_still_counts() -> None:
    limiter = Limiter()
    rule = Rule(limit=1, window_seconds=60)
    limiter.check("a", rule, now=0.0)
    first = limiter.check("a", rule, now=0.0)
    second = limiter.check("a", rule, now=0.0)
    # Rejected requests must not be free: a client that keeps sending stays
    # refused for the rest of the window.
    assert first.allowed is False
    assert second.allowed is False
    assert second.remaining == 0


def test_the_window_turns_over() -> None:
    limiter = Limiter()
    rule = Rule(limit=1, window_seconds=10)
    assert limiter.check("a", rule, now=0.0).allowed
    assert not limiter.check("a", rule, now=5.0).allowed
    # A fixed window, so this is exactly predictable, which is the whole
    # reason for choosing one over a token bucket.
    assert limiter.check("a", rule, now=10.0).allowed


def test_retry_after_counts_down_to_the_turnover() -> None:
    limiter = Limiter()
    rule = Rule(limit=1, window_seconds=60)
    assert limiter.check("a", rule, now=0.0).retry_after == 60
    assert limiter.check("a", rule, now=50.0).retry_after == 10
    # Never zero: a client told to retry in no time retries immediately.
    assert limiter.check("a", rule, now=59.9).retry_after == 1


def test_clients_are_counted_separately() -> None:
    limiter = Limiter()
    rule = Rule(limit=1, window_seconds=60)
    assert limiter.check("a", rule, now=0.0).allowed
    # One organisation's runaway job must not consume another's allowance.
    assert limiter.check("b", rule, now=0.0).allowed


def test_the_counter_table_is_bounded() -> None:
    limiter = Limiter(max_tracked=10)
    rule = Rule(limit=1, window_seconds=60)
    for index in range(1000):
        limiter.check(f"client-{index}", rule, now=0.0)
    # Anybody who can vary the key can otherwise grow this without limit, and
    # the limiter becomes the denial of service.
    assert limiter.tracked == 10


def test_eviction_forgets_the_oldest_rather_than_the_busiest() -> None:
    limiter = Limiter(max_tracked=2)
    rule = Rule(limit=5, window_seconds=60)
    limiter.check("old", rule, now=0.0)
    limiter.check("busy", rule, now=0.0)
    limiter.check("busy", rule, now=0.0)
    limiter.check("new", rule, now=0.0)
    # "old" goes, not "busy": a client still sending is the one worth
    # remembering, and evicting it would hand it an unlimited allowance.
    assert limiter.check("busy", rule, now=0.0).remaining == 2


def test_a_rule_has_to_be_positive() -> None:
    for limit, window in ((0, 60), (10, 0), (-1, 60)):
        with pytest.raises(ValueError, match="positive limit and window"):
            Rule(limit=limit, window_seconds=window)


def test_an_identity_is_not_the_key_it_came_from() -> None:
    secret = "vexpath_live_" + "k" * 43
    identity = identity_from_key(secret)
    # A limiter whose state can be dumped in a heap profile must not be a
    # place credentials are kept.
    assert secret not in identity
    assert len(identity) == 16
    assert identity == identity_from_key(f"  {secret}  ")
    assert identity != identity_from_key("vexpath_live_" + "j" * 43)


def test_reset_clears_everything() -> None:
    limiter = Limiter()
    limiter.check("a", Rule(limit=1, window_seconds=60), now=0.0)
    limiter.reset()
    assert limiter.tracked == 0
