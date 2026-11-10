"""Suppressions: deciding not to fix something, on the record.

A suppression says "we know about this and chose not to act". That is a
legitimate and common decision, and a tool that offers no way to record it gets
one anyway -- as a `grep -v` in a CI script, or as a threshold nobody revisits,
or as a team that stops reading the output. So this exists, and the shape of it
is designed around the two ways it goes wrong.

**A suppression with no expiry outlives the reason for it.** The database makes
``expires_at`` not nullable, this module refuses an unreasonably distant one,
and the pages show how long is left. Somebody has to look again, which is the
only property that distinguishes a suppression from a deletion.

**A suppression with no reason cannot be reviewed.** The column is not
nullable and blank text is refused. An unreviewable suppression is how a
vulnerability stays hidden after the person who hid it has left.

And one thing a suppression is **not**: a change to the facts. It never alters
a reachability verdict, never rewrites a finding's severity, and never changes
what the public report or the badge says about reachable code. A badge reading
"none reachable" because somebody suppressed the reachable one would be the
most misleading artefact this system could produce. Suppression is a workflow
state attached to a finding, and the evidence underneath it stays exactly as
the analysis left it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

#: The longest a suppression may run. Two years is already longer than most
#: teams keep the context that justified one; beyond that the expiry is a
#: formality, which is the thing an expiry exists to prevent.
MAX_DURATION = timedelta(days=730)

#: The default when somebody does not choose. Ninety days is long enough to
#: ship a planned upgrade and short enough that a forgotten suppression comes
#: back while anybody still remembers it.
DEFAULT_DAYS = 90

#: Longest reason text stored. Generous: the reason is the whole point, and
#: truncating somebody's explanation of a security decision is worse than
#: storing a long one.
MAX_REASON = 2000


class SuppressionError(ValueError):
    """A suppression that must not be stored, with the reason why."""


@dataclass(frozen=True, slots=True)
class SuppressionRequest:
    """A validated suppression, ready to insert."""

    advisory_id: str
    reason: str
    expires_at: datetime
    #: None means every component of the project. The broader and therefore
    #: more dangerous choice, so it is explicit rather than the default.
    purl: str | None = None
    justification: str | None = None


def build(
    *,
    advisory_id: str,
    reason: str,
    days: int | None = None,
    purl: str | None = None,
    justification: str | None = None,
    moment: datetime | None = None,
) -> SuppressionRequest:
    """Validate and normalise a suppression.

    Raises:
        SuppressionError: if the advisory is missing, the reason is blank, or
            the duration is outside what this system will record. Each message
            says what to do instead, because every one of these is somebody
            filling in a form rather than an attack.
    """
    identifier = advisory_id.strip()
    if not identifier:
        msg = "a suppression has to name an advisory"
        raise SuppressionError(msg)

    explanation = reason.strip()
    if not explanation:
        msg = (
            "a suppression needs a reason. A suppression nobody explained is "
            "one nobody can review, and an unreviewable suppression is how a "
            "vulnerability stays hidden"
        )
        raise SuppressionError(msg)
    explanation = explanation[:MAX_REASON]

    duration = timedelta(days=DEFAULT_DAYS if days is None else days)
    if duration <= timedelta(0):
        msg = "a suppression has to last at least a day"
        raise SuppressionError(msg)
    if duration > MAX_DURATION:
        msg = (
            f"a suppression can run for at most {MAX_DURATION.days} days. "
            f"Beyond that the expiry is a formality, which is the thing an "
            f"expiry exists to prevent"
        )
        raise SuppressionError(msg)

    return SuppressionRequest(
        advisory_id=identifier,
        reason=explanation,
        expires_at=(moment or datetime.now(UTC)) + duration,
        purl=(purl or "").strip() or None,
        justification=(justification or "").strip() or None,
    )


def is_active(row: Any, *, moment: datetime | None = None) -> bool:
    """Whether a stored suppression applies right now.

    Expiry is checked here as well as being a column, because nothing deletes
    an expired row: the history of what was suppressed and why is worth more
    than a tidy table, and a row that lingers must not keep working.
    """
    if row["revoked_at"] is not None:
        return False
    expires: datetime = row["expires_at"]
    return expires > (moment or datetime.now(UTC))


def matches(row: Any, *, advisory_id: str, purl: str) -> bool:
    """Whether one suppression covers one finding.

    A null ``purl`` covers every component, which is why creating one is a
    deliberate choice rather than a default. Matching is exact on both fields:
    a prefix or glob match would let a suppression written for one package
    quietly cover a package added later whose name happens to start the same
    way.
    """
    if row["advisory_id"] != advisory_id:
        return False
    return row["purl"] is None or row["purl"] == purl


def applicable(
    rows: list[Any], *, advisory_id: str, purl: str, moment: datetime | None = None
) -> Any:
    """The suppression that covers a finding, or None.

    The most specific wins: a suppression naming this exact component is
    preferred over a project-wide one, so revoking the broad one does not
    silently unsuppress something that had its own entry.
    """
    candidates = [
        row
        for row in rows
        if is_active(row, moment=moment) and matches(row, advisory_id=advisory_id, purl=purl)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda row: (row["purl"] is None, row["expires_at"]))
    return candidates[0]


def remaining_days(row: Any, *, moment: datetime | None = None) -> int:
    """Whole days until this suppression expires, never below zero.

    Shown on the pages, because "expires 2027-02-14" is a date and "expires in
    11 days" is a prompt to do something about it.
    """
    expires: datetime = row["expires_at"]
    delta = expires - (moment or datetime.now(UTC))
    return max(0, delta.days)


__all__ = [
    "DEFAULT_DAYS",
    "MAX_DURATION",
    "MAX_REASON",
    "SuppressionError",
    "SuppressionRequest",
    "applicable",
    "build",
    "is_active",
    "matches",
    "remaining_days",
]
