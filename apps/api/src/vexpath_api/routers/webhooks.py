"""``/v1/webhooks``: registering an endpoint to be called.

The feature where a user hands this system an address and it connects to it,
which makes it server-side request forgery by design. What keeps it safe lives
in ``vexpath_platform.outbound``; what this router adds is that the refusal is
explained. "That URL is not allowed" sends somebody to a support channel;
"a webhook can only be delivered to the public internet, because an address on
this network would reach services only reachable from inside" tells them what
to change.

The signing secret is shown once, in the response that created the webhook,
exactly as an API key is. Unlike a key it is also stored — encrypted, because
an HMAC needs the secret back — and the rotate endpoint exists so a leaked one
can be replaced without recreating the subscription and losing its history.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_api.auth import Authenticated, TenantConnection
from vexpath_api.dependencies import get_engine, get_settings_from_app
from vexpath_api.webhooks import EVENTS, deliver
from vexpath_core.ids import new_ulid
from vexpath_db.tables import audit_log, projects, webhook_deliveries, webhooks
from vexpath_platform import outbound, secretbox
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/v1/webhooks", tags=["webhooks"])


class WebhookIn(BaseModel):
    """What a caller supplies to register a webhook."""

    url: str = Field(min_length=8, max_length=2000)
    #: Which events. No default: a subscription to everything is a decision,
    #: and one arrived at by leaving a field out is not.
    events: list[str] = Field(min_length=1)
    #: Null means every project of the organisation. The broader choice, so a
    #: client has to say it.
    project: str | None = None
    description: str | None = Field(default=None, max_length=200)


class WebhookOut(BaseModel):
    """A webhook as the API returns it. Never carries the secret."""

    id: str
    url: str
    events: list[str]
    project_id: str | None
    description: str | None
    active: bool
    secret_fingerprint: str
    failure_count: int
    disabled_at: datetime | None
    last_delivery_at: datetime | None
    created_at: datetime
    delivery_count: int = 0


class WebhookCreated(WebhookOut):
    """The one response that carries the signing secret.

    Separate from ``WebhookOut`` so the field cannot appear on a list or a
    read by somebody adding a line to the wrong model.
    """

    secret: str


class DeliveryOut(BaseModel):
    """One delivery attempt."""

    id: str
    event: str
    status: str
    attempts: int
    response_status: int | None
    error: str | None
    created_at: datetime
    completed_at: datetime | None


@router.get("", response_model=list[WebhookOut], summary="List webhooks")
async def list_webhooks(connection: TenantConnection) -> list[WebhookOut]:
    rows = (
        await connection.execute(
            select(webhooks, func.count(webhook_deliveries.c.id).label("delivery_count"))
            .outerjoin(webhook_deliveries, webhook_deliveries.c.webhook_id == webhooks.c.id)
            .group_by(webhooks.c.id)
            .order_by(webhooks.c.created_at.desc())
            .limit(200)
        )
    ).mappings()
    return [_to_out(row) for row in rows]


@router.post(
    "",
    response_model=WebhookCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Register a webhook",
)
async def create_webhook(
    payload: WebhookIn, request: Request, connection: TenantConnection, principal: Authenticated
) -> WebhookCreated:
    """Register an endpoint, and return its signing secret once.

    Raises:
        HTTPException: 422 for a URL this system will not connect to or an
            unknown event name, 404 if the named project is not the caller's.
    """
    try:
        outbound.check_url(payload.url)
    except outbound.UrlRefusedError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from None

    unknown = sorted(set(payload.events) - set(EVENTS))
    if unknown:
        # Refused rather than stored. A subscription to an event nobody emits
        # looks like a working subscription and is silence.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"unknown event{'s' if len(unknown) > 1 else ''}: {', '.join(unknown)}. "
                f"Available: {', '.join(EVENTS)}"
            ),
        )

    project_id = await _project_id(connection, payload.project) if payload.project else None

    settings = get_settings_from_app(request)
    secret = outbound.new_secret()
    identifier = new_ulid()
    await connection.execute(
        insert(webhooks).values(
            id=identifier,
            org_id=principal.org_id,
            project_id=project_id,
            url=payload.url.strip(),
            # Encrypted rather than hashed: an HMAC needs the secret back.
            secret_encrypted=secretbox.seal(settings.secret_key, secret),
            secret_fingerprint=outbound.fingerprint(secret),
            events=sorted(set(payload.events)),
            description=payload.description,
        )
    )
    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=principal.org_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            action="webhook.created",
            target_type="webhook",
            target_id=identifier,
            # The URL, never the secret: an audit log is read by more people
            # than a credential should be.
            metadata={"url": payload.url.strip(), "events": sorted(set(payload.events))},
        )
    )
    log.info("api.webhook.created", org=principal.org_id, webhook=identifier)

    stored = await _fetch(connection, identifier)
    return WebhookCreated(**stored.model_dump(), secret=secret)


@router.get("/{webhook_id}", response_model=WebhookOut, summary="Read one webhook")
async def read_webhook(webhook_id: str, connection: TenantConnection) -> WebhookOut:
    return await _fetch(connection, webhook_id)


@router.get(
    "/{webhook_id}/deliveries", response_model=list[DeliveryOut], summary="Delivery history"
)
async def list_deliveries(
    webhook_id: str,
    connection: TenantConnection,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[DeliveryOut]:
    """What happened on recent deliveries.

    The outcome and the error, never the payload: a delivery carries findings,
    and a second copy of them in a log doubles the places a leak can come
    from.
    """
    await _fetch(connection, webhook_id)
    rows = (
        await connection.execute(
            select(webhook_deliveries)
            .where(webhook_deliveries.c.webhook_id == webhook_id)
            .order_by(webhook_deliveries.c.created_at.desc())
            .limit(limit)
        )
    ).mappings()
    return [
        DeliveryOut(
            id=row["id"],
            event=row["event"],
            status=row["status"],
            attempts=row["attempts"],
            response_status=row["response_status"],
            error=row["error"],
            created_at=row["created_at"],
            completed_at=row["completed_at"],
        )
        for row in rows
    ]


@router.post("/{webhook_id}/ping", response_model=DeliveryOut, summary="Send a test delivery")
async def ping(webhook_id: str, request: Request, connection: TenantConnection) -> DeliveryOut:
    """Deliver a ``ping`` now, and return what happened.

    Synchronous on purpose, unlike a real event. Somebody who has just pasted
    a URL wants to know whether it works, and a test whose result arrives in a
    log five minutes later is a test nobody runs.
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
    # Committed before the delivery runs: the delivery opens its own
    # connections to record its outcome, and holding this transaction open
    # across a network call to somebody else's server would pin a connection
    # for as long as they take to answer.
    await connection.commit()

    delivery_id = await deliver(
        engine,
        secret_key=settings.secret_key,
        webhook=dict(row),
        event="ping",
        payload={"message": "This is a test delivery from vexpath."},
    )

    async with engine.begin() as fresh:
        from vexpath_db.tenancy import async_tenant_context

        async with async_tenant_context(fresh, str(row["org_id"])) as scoped:
            delivery = (
                (
                    await scoped.execute(
                        select(webhook_deliveries).where(webhook_deliveries.c.id == delivery_id)
                    )
                )
                .mappings()
                .one()
            )
    return DeliveryOut(
        id=delivery["id"],
        event=delivery["event"],
        status=delivery["status"],
        attempts=delivery["attempts"],
        response_status=delivery["response_status"],
        error=delivery["error"],
        created_at=delivery["created_at"],
        completed_at=delivery["completed_at"],
    )


@router.post("/{webhook_id}/rotate", response_model=WebhookCreated, summary="Rotate the secret")
async def rotate(
    webhook_id: str, request: Request, connection: TenantConnection, principal: Authenticated
) -> WebhookCreated:
    """Replace the signing secret, and return the new one once.

    Exists so a leaked secret can be replaced without deleting the webhook,
    which would lose its delivery history -- and the history is how somebody
    works out whether the leak was used.
    """
    settings = get_settings_from_app(request)
    secret = outbound.new_secret()
    result = await connection.execute(
        update(webhooks)
        .where(webhooks.c.id == webhook_id)
        .values(
            secret_encrypted=secretbox.seal(settings.secret_key, secret),
            secret_fingerprint=outbound.fingerprint(secret),
        )
        .returning(webhooks.c.id)
    )
    if result.one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such webhook")

    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=principal.org_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            action="webhook.secret_rotated",
            target_type="webhook",
            target_id=webhook_id,
            metadata={},
        )
    )
    stored = await _fetch(connection, webhook_id)
    return WebhookCreated(**stored.model_dump(), secret=secret)


@router.post("/{webhook_id}/enable", response_model=WebhookOut, summary="Re-enable a webhook")
async def enable(webhook_id: str, connection: TenantConnection) -> WebhookOut:
    """Turn a disabled webhook back on and forget its failures.

    A webhook switched off after twenty consecutive failures stays off until
    somebody says the receiver is fixed. Clearing the count here is what makes
    that statement, rather than the next delivery disabling it again on its
    first retry.
    """
    result = await connection.execute(
        update(webhooks)
        .where(webhooks.c.id == webhook_id)
        .values(active=True, disabled_at=None, failure_count=0)
        .returning(webhooks.c.id)
    )
    if result.one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such webhook")
    return await _fetch(connection, webhook_id)


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a webhook")
async def delete_webhook(
    webhook_id: str, connection: TenantConnection, principal: Authenticated
) -> None:
    """Delete a webhook and its delivery history.

    Deleted rather than marked, unlike a suppression: a webhook is a piece of
    configuration rather than a decision, and nobody needs to know later that
    an endpoint used to be subscribed. The audit log records that it was
    removed.
    """
    result = await connection.execute(
        webhooks.delete().where(webhooks.c.id == webhook_id).returning(webhooks.c.id)
    )
    if result.one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such webhook")
    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=principal.org_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            action="webhook.deleted",
            target_type="webhook",
            target_id=webhook_id,
            metadata={},
        )
    )


async def _project_id(connection: AsyncConnection, slug: str) -> str:
    row = (
        await connection.execute(select(projects.c.id).where(projects.c.slug == slug))
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such project")
    return str(row.id)


async def _fetch(connection: AsyncConnection, identifier: str) -> WebhookOut:
    row = (
        (
            await connection.execute(
                select(webhooks, func.count(webhook_deliveries.c.id).label("delivery_count"))
                .outerjoin(webhook_deliveries, webhook_deliveries.c.webhook_id == webhooks.c.id)
                .where(webhooks.c.id == identifier)
                .group_by(webhooks.c.id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        # 404 for another organisation's webhook as well as for one that does
        # not exist. The connection cannot see it either way.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such webhook")
    return _to_out(row)


def _to_out(row: Any) -> WebhookOut:
    return WebhookOut(
        id=row["id"],
        url=row["url"],
        events=list(row["events"] or []),
        project_id=row["project_id"],
        description=row["description"],
        active=row["active"],
        secret_fingerprint=row["secret_fingerprint"],
        failure_count=row["failure_count"],
        disabled_at=row["disabled_at"],
        last_delivery_at=row["last_delivery_at"],
        created_at=row["created_at"],
        delivery_count=int(row["delivery_count"] or 0),
    )


__all__ = ["router"]
