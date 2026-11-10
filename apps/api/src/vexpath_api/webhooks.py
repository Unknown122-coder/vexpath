"""Delivering webhooks.

The outbound half of the feature. ``vexpath_platform.outbound`` decides what a
URL is allowed to be; this decides what happens when one is called.

**Every delivery re-resolves the hostname and re-checks the addresses.** A name
that resolved to a public address when the webhook was registered can resolve
to ``127.0.0.1`` today, and validating once at registration is exactly the DNS
rebinding bypass. There remains a narrow window between this check and the
connection the HTTP client makes, because the client resolves the name again
itself; closing it entirely means connecting to a pinned address while keeping
the certificate check for the hostname, which is work for a later pass. The
window is written down here rather than left for somebody to assume it is not
there.

**A delivery is retried, but not forever and not immediately.** Three attempts
with widening gaps covers the restart and the brief blip, which is what
retrying is for. Beyond that the receiver is down, and a sender that keeps
trying becomes a load generator pointed at somebody who is already struggling.
After enough consecutive failures the webhook is disabled rather than deleted,
so somebody can see why it stopped.

**The payload is never stored.** A delivery carries findings; a log table
holding a second copy of them doubles the places a leak can come from and adds
nothing a digest does not already answer. The delivery row keeps the outcome
and the body's SHA-256.

**A refused URL is recorded as refused, not as failed.** "We would not connect
there" and "they did not answer" need different fixes, and a log that calls
both failures sends somebody to check their server when the problem is their
address.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from vexpath_core.ids import new_ulid
from vexpath_db.tables import webhook_deliveries, webhooks
from vexpath_db.tenancy import async_tenant_context
from vexpath_platform import outbound, secretbox
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

#: The events a webhook can ask for. A closed vocabulary, because a
#: subscription to an event name nobody emits looks like a working
#: subscription and is silence.
EVENTS = (
    "ping",
    "scan.completed",
    "finding.new_reachable",
)

#: Attempts per delivery, and the gaps between them. Three attempts covers a
#: restart and a blip; past that the receiver is down and more attempts only
#: add load to somebody already struggling.
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (1.0, 4.0)

#: Consecutive failures before a webhook is switched off. High enough to
#: survive an afternoon of trouble, low enough that a receiver deleted months
#: ago is not still being called.
FAILURE_THRESHOLD = 20

#: How long to wait for the receiver. Short: a delivery is a notification, and
#: an endpoint that takes half a minute to accept one is going to be retried
#: anyway.
TIMEOUT = 10.0

#: Most of a response body to keep for diagnostics. Enough to show an error
#: page's first line, little enough that a receiver answering with megabytes
#: cannot fill the log.
MAX_ERROR_BYTES = 500

#: Resolves a hostname to addresses. Injectable, and that is what makes the
#: validation testable: a test can answer with one public and one loopback
#: address, which is the bypass that matters and the one real DNS will never
#: hand you on demand. Nothing in the application passes anything but the
#: default, so there is no flag that could weaken this in a deployment.
Resolver = Callable[[str], Awaitable[list[str]]]


async def resolve(host: str) -> list[str]:
    """Every address a hostname resolves to.

    On the loop's executor, because ``getaddrinfo`` blocks and blocking the
    loop to check one address would make a slow DNS server everybody's
    problem.
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        msg = f"{host} could not be resolved: {exc}"
        raise outbound.UrlRefusedError(msg) from exc
    return [str(info[4][0]) for info in infos]


async def dispatch(
    engine: AsyncEngine,
    *,
    secret_key: str,
    org_id: str,
    project_id: str | None,
    event: str,
    payload: dict[str, Any],
    resolver: Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[str]:
    """Deliver one event to every webhook that asked for it.

    Returns the delivery identifiers. Failures are recorded and never raised:
    this runs after the request that caused it has been answered, and an
    upload must not fail because somebody's notification endpoint is down.
    """
    if event not in EVENTS:
        # A programming error rather than a user's: an event nobody can
        # subscribe to would be delivered to nobody and look like it worked.
        log.warning("api.webhook.unknown_event", name=event)
        return []

    async with engine.begin() as connection, async_tenant_context(connection, org_id) as scoped:
        rows = [
            dict(row)
            for row in (
                await scoped.execute(
                    select(webhooks).where(
                        webhooks.c.active.is_(True) & webhooks.c.disabled_at.is_(None)
                    )
                )
            ).mappings()
        ]

    targets = [
        row
        for row in rows
        if event in (row["events"] or [])
        # A webhook with no project covers every project of the organisation.
        and (row["project_id"] is None or row["project_id"] == project_id)
    ]

    deliveries: list[str] = []
    for row in targets:
        deliveries.append(
            await deliver(
                engine,
                secret_key=secret_key,
                webhook=row,
                event=event,
                payload=payload,
                resolver=resolver,
                transport=transport,
            )
        )
    return deliveries


async def deliver(
    engine: AsyncEngine,
    *,
    secret_key: str,
    webhook: dict[str, Any],
    event: str,
    payload: dict[str, Any],
    resolver: Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    """Send one payload to one webhook, retrying briefly, and record what
    happened.

    Returns the delivery identifier.
    """
    org_id = str(webhook["org_id"])
    delivery_id = new_ulid()
    # Separators without spaces and sorted keys: the body is signed, so it has
    # to serialise to the same bytes the signature was computed over, and a
    # receiver that re-serialises to verify must be able to reproduce it.
    body = json.dumps(
        {"event": event, "delivery": delivery_id, "data": payload},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()

    await _record(
        engine,
        org_id,
        insert(webhook_deliveries).values(
            id=delivery_id,
            org_id=org_id,
            webhook_id=webhook["id"],
            event=event,
            status="pending",
            attempts=0,
            payload_sha256=digest,
        ),
    )

    try:
        secret = secretbox.unseal(secret_key, str(webhook["secret_encrypted"]))
    except secretbox.UnreadableSecretError as exc:
        # Expected after VEXPATH_SECRET_KEY is rotated, so it is reported as
        # something to re-issue rather than as a failure of the receiver.
        await _finish(engine, org_id, delivery_id, status="refused", error=str(exc), attempts=0)
        return delivery_id

    outcome = await _attempt_all(
        secret,
        webhook,
        event,
        delivery_id,
        body,
        resolver=resolver or resolve,
        transport=transport,
    )
    await _finish(
        engine,
        org_id,
        delivery_id,
        status=outcome["status"],
        error=outcome["error"],
        attempts=outcome["attempts"],
        response_status=outcome["response_status"],
    )
    await _update_health(
        engine, org_id, str(webhook["id"]), delivered=outcome["status"] == "delivered"
    )
    return delivery_id


async def _attempt_all(
    secret: str,
    webhook: dict[str, Any],
    event: str,
    delivery_id: str,
    body: bytes,
    *,
    resolver: Resolver,
    transport: httpx.AsyncBaseTransport | None,
) -> dict[str, Any]:
    """Try the delivery, up to the attempt limit."""
    url = str(webhook["url"])
    last_error: str | None = None
    response_status: int | None = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            # Re-validated on every attempt, not once at registration: a name
            # that resolved publicly an hour ago can resolve to loopback now,
            # and trusting the earlier answer is the rebinding bypass.
            target = outbound.check_url(url)
            outbound.refuse_private_addresses(target.host, await resolver(target.host))
        except outbound.UrlRefusedError as exc:
            # Not a failure of the receiver, so it is not retried: the address
            # will not become acceptable on the next attempt.
            return {
                "status": "refused",
                "error": str(exc),
                "attempts": attempt,
                "response_status": None,
            }

        timestamp = int(time.time())
        try:
            async with httpx.AsyncClient(
                timeout=TIMEOUT,
                # A redirect is a second URL that nothing validated.
                follow_redirects=False,
                transport=transport,
            ) as client:
                response = await client.post(
                    url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "vexpath-webhook/1",
                        outbound.SIGNATURE_HEADER: outbound.sign(secret, timestamp, body),
                        outbound.TIMESTAMP_HEADER: str(timestamp),
                        outbound.EVENT_HEADER: event,
                        outbound.DELIVERY_HEADER: delivery_id,
                    },
                )
        except httpx.HTTPError as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        else:
            response_status = response.status_code
            if 200 <= response.status_code < 300:
                return {
                    "status": "delivered",
                    "error": None,
                    "attempts": attempt,
                    "response_status": response.status_code,
                }
            if 300 <= response.status_code < 400:
                # Reported in its own words, because "we do not follow
                # redirects" is a configuration answer and not an outage.
                return {
                    "status": "refused",
                    "error": (
                        f"the endpoint answered {response.status_code} with a redirect, "
                        f"which is not followed: a redirect is a second URL that nothing "
                        f"validated. Register the final URL instead."
                    ),
                    "attempts": attempt,
                    "response_status": response.status_code,
                }
            last_error = f"the endpoint answered {response.status_code}: " + _excerpt(response)

        if attempt <= len(BACKOFF_SECONDS):
            await asyncio.sleep(BACKOFF_SECONDS[attempt - 1])

    return {
        "status": "failed",
        "error": last_error,
        "attempts": MAX_ATTEMPTS,
        "response_status": response_status,
    }


def _excerpt(response: httpx.Response) -> str:
    """The first of a response body, for a diagnostic.

    Bounded, because a receiver answering an error with megabytes of HTML must
    not be able to fill this log.
    """
    try:
        return response.text[:MAX_ERROR_BYTES]
    except (UnicodeDecodeError, httpx.HTTPError):
        return "<unreadable body>"


async def _record(engine: AsyncEngine, org_id: str, statement: Any) -> None:
    async with engine.begin() as connection, async_tenant_context(connection, org_id) as scoped:
        await scoped.execute(statement)


async def _finish(
    engine: AsyncEngine,
    org_id: str,
    delivery_id: str,
    *,
    status: str,
    error: str | None,
    attempts: int,
    response_status: int | None = None,
) -> None:
    from datetime import UTC, datetime

    await _record(
        engine,
        org_id,
        update(webhook_deliveries)
        .where(webhook_deliveries.c.id == delivery_id)
        .values(
            status=status,
            attempts=attempts,
            response_status=response_status,
            error=error[:2000] if error else None,
            completed_at=datetime.now(UTC),
        ),
    )
    log.info("api.webhook.delivery", delivery=delivery_id, status=status, attempts=attempts)


async def _update_health(
    engine: AsyncEngine, org_id: str, webhook_id: str, *, delivered: bool
) -> None:
    """Count the failure, and switch the webhook off if there have been enough.

    Disabled rather than deleted: somebody has to be able to see that it
    stopped and why, and a webhook that vanished would look like one that was
    never created.
    """
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    if delivered:
        await _record(
            engine,
            org_id,
            update(webhooks)
            .where(webhooks.c.id == webhook_id)
            .values(failure_count=0, last_delivery_at=now, disabled_at=None),
        )
        return

    async with engine.begin() as connection, async_tenant_context(connection, org_id) as scoped:
        current = (
            await scoped.execute(
                select(webhooks.c.failure_count).where(webhooks.c.id == webhook_id)
            )
        ).scalar_one_or_none()
        failures = int(current or 0) + 1
        await scoped.execute(
            update(webhooks)
            .where(webhooks.c.id == webhook_id)
            .values(
                failure_count=failures,
                last_delivery_at=now,
                disabled_at=now if failures >= FAILURE_THRESHOLD else None,
            )
        )
    if failures >= FAILURE_THRESHOLD:
        log.warning("api.webhook.disabled", webhook=webhook_id, failures=failures)


__all__ = [
    "BACKOFF_SECONDS",
    "EVENTS",
    "FAILURE_THRESHOLD",
    "MAX_ATTEMPTS",
    "TIMEOUT",
    "Resolver",
    "deliver",
    "dispatch",
    "resolve",
]
