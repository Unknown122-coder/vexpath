"""The webhooks screen.

The API can register a webhook; this is where a person does it, which matters
because the refusals are the point of the feature and a refusal is only useful
if somebody reads it. The form shows the rule before it is broken — https, a
public address, port 443 — and the error says which rule and why.

The delivery history is on the same page rather than behind a link. "I
registered it and nothing arrived" is the only question anybody asks about a
webhook, and the answer is always in the last few attempts: refused for an
address, failed with a 500, or delivered and the receiver dropped it.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_api.dependencies import get_engine, get_settings_from_app
from vexpath_api.session import CsrfVerified, RequiredSession, SessionConnection
from vexpath_api.templating import render
from vexpath_api.webhooks import EVENTS, deliver
from vexpath_core.ids import new_ulid
from vexpath_db.tables import audit_log, projects, webhook_deliveries, webhooks
from vexpath_platform import outbound, secretbox
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/app", tags=["dashboard"], include_in_schema=False)

#: How many past attempts to show. Enough to see a pattern, few enough that
#: the page stays about the webhook rather than about its log.
HISTORY = 10


@router.get("/webhooks", response_class=HTMLResponse, summary="Webhooks")
async def webhooks_page(
    request: Request,
    session: RequiredSession,
    connection: SessionConnection,
) -> HTMLResponse:
    """The organisation's webhooks and their recent deliveries."""
    return render(
        request,
        "app_webhooks.html",
        {
            "session": session,
            "webhooks": await _webhooks(connection),
            "events": EVENTS,
            "allowed_ports": sorted(outbound.ALLOWED_PORTS),
            "issued": None,
            "problem": None,
        },
    )


@router.post("/webhooks", response_class=HTMLResponse, response_model=None, summary="Add a webhook")
async def create(
    request: Request,
    session: CsrfVerified,
    connection: SessionConnection,
    url: Annotated[str, Form()] = "",
    events: Annotated[list[str], Form()] = [],  # noqa: B006 - Form needs a real default
    project: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
) -> HTMLResponse | RedirectResponse:
    """Register an endpoint and show its signing secret once.

    Answers with the page rather than a redirect, for the same reason the API
    key screen does: a redirect would have to carry the secret in a URL, where
    it would land in browser history, in a proxy log, and in the next
    request's ``Referer`` header.
    """
    chosen = [event for event in events if event in EVENTS]
    problem: str | None = None
    if not chosen:
        problem = "Choose at least one event. A webhook subscribed to nothing is silence."
    else:
        try:
            outbound.check_url(url)
        except outbound.UrlRefusedError as exc:
            # The whole refusal, verbatim. It was written for this screen.
            problem = str(exc)

    project_id: str | None = None
    if problem is None and project:
        project_id = (
            await connection.execute(select(projects.c.id).where(projects.c.slug == project))
        ).scalar_one_or_none()
        if project_id is None:
            # Unquoted: autoescaping turns a quote into an entity, and a
            # message reading "called &#39;nope&#39;" is worse than no quotes.
            problem = f"There is no project called {project} in this organisation."

    if problem is not None:
        return render(
            request,
            "app_webhooks.html",
            {
                "session": session,
                "webhooks": await _webhooks(connection),
                "events": EVENTS,
                "allowed_ports": sorted(outbound.ALLOWED_PORTS),
                "issued": None,
                "problem": problem,
                # So the form comes back filled in rather than blank.
                "submitted": {"url": url, "events": chosen, "project": project},
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    settings = get_settings_from_app(request)
    secret = outbound.new_secret()
    identifier = new_ulid()
    await connection.execute(
        insert(webhooks).values(
            id=identifier,
            org_id=session.org_id,
            project_id=project_id,
            url=url.strip(),
            secret_encrypted=secretbox.seal(settings.secret_key, secret),
            secret_fingerprint=outbound.fingerprint(secret),
            events=sorted(set(chosen)),
            description=description.strip() or None,
            created_by=session.user_id,
        )
    )
    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=session.org_id,
            actor_type="user",
            actor_id=session.user_id,
            action="webhook.created",
            target_type="webhook",
            target_id=identifier,
            metadata={"url": url.strip(), "events": sorted(set(chosen)), "login": session.login},
        )
    )
    log.info("app.webhook.created", org=session.org_id, webhook=identifier)

    return render(
        request,
        "app_webhooks.html",
        {
            "session": session,
            "webhooks": await _webhooks(connection),
            "events": EVENTS,
            "allowed_ports": sorted(outbound.ALLOWED_PORTS),
            # The only moment this value is rendered.
            "issued": {"secret": secret, "url": url.strip()},
            "problem": None,
        },
        status_code=status.HTTP_201_CREATED,
    )


@router.post("/webhooks/{webhook_id}/ping", summary="Send a test delivery")
async def ping(
    webhook_id: str, request: Request, session: CsrfVerified, connection: SessionConnection
) -> RedirectResponse:
    """Deliver a ``ping`` now.

    Synchronous, unlike a real event: somebody who has just pasted a URL wants
    to know whether it works, and a test whose result appears in a log five
    minutes later is a test nobody runs.
    """
    row = (
        (await connection.execute(select(webhooks).where(webhooks.c.id == webhook_id)))
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such webhook")

    settings = get_settings_from_app(request)
    engine = get_engine(request)
    # Committed first: the delivery opens its own connections, and holding
    # this transaction across a network call to somebody else's server would
    # pin a connection for as long as they take to answer.
    await connection.commit()

    await deliver(
        engine,
        secret_key=settings.secret_key,
        webhook=dict(row),
        event="ping",
        payload={"message": "This is a test delivery from vexpath."},
    )
    return RedirectResponse("/app/webhooks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/webhooks/{webhook_id}/enable", summary="Re-enable a webhook")
async def enable(
    webhook_id: str, session: CsrfVerified, connection: SessionConnection
) -> RedirectResponse:
    """Turn a disabled webhook back on and clear its failure count.

    Clearing the count is what makes this a statement that the receiver is
    fixed; without it the next delivery's first retry would disable it again.
    """
    del session
    await connection.execute(
        update(webhooks)
        .where(webhooks.c.id == webhook_id)
        .values(active=True, disabled_at=None, failure_count=0)
    )
    return RedirectResponse("/app/webhooks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/webhooks/{webhook_id}/delete", summary="Delete a webhook")
async def remove(
    webhook_id: str, session: CsrfVerified, connection: SessionConnection
) -> RedirectResponse:
    """Delete a webhook.

    A POST to its own URL rather than a DELETE: a browser form can only send
    GET or POST, and tunnelling a method through a hidden field would be
    pretending the form is something it is not.
    """
    await connection.execute(webhooks.delete().where(webhooks.c.id == webhook_id))
    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=session.org_id,
            actor_type="user",
            actor_id=session.user_id,
            action="webhook.deleted",
            target_type="webhook",
            target_id=webhook_id,
            metadata={"login": session.login},
        )
    )
    return RedirectResponse("/app/webhooks", status_code=status.HTTP_303_SEE_OTHER)


async def _webhooks(connection: AsyncConnection) -> list[dict[str, Any]]:
    """Every webhook with its recent deliveries attached.

    Two queries rather than one per webhook: "nothing arrived" is the only
    question anybody asks, and the answer is in the last few attempts, so the
    history belongs on this page and not behind a link.
    """
    rows = [
        dict(row)
        for row in (
            await connection.execute(
                select(webhooks, func.count(webhook_deliveries.c.id).label("delivery_count"))
                .outerjoin(webhook_deliveries, webhook_deliveries.c.webhook_id == webhooks.c.id)
                .group_by(webhooks.c.id)
                .order_by(webhooks.c.created_at.desc())
                .limit(50)
            )
        ).mappings()
    ]
    if not rows:
        return []

    recent = (
        await connection.execute(
            select(webhook_deliveries)
            .where(webhook_deliveries.c.webhook_id.in_([row["id"] for row in rows]))
            .order_by(webhook_deliveries.c.created_at.desc())
            .limit(len(rows) * HISTORY)
        )
    ).mappings()

    by_hook: dict[str, list[dict[str, Any]]] = {}
    for delivery in recent:
        entries = by_hook.setdefault(delivery["webhook_id"], [])
        if len(entries) < HISTORY:
            entries.append(dict(delivery))
    for row in rows:
        row["deliveries"] = by_hook.get(row["id"], [])
    return rows


__all__ = ["HISTORY", "router"]
