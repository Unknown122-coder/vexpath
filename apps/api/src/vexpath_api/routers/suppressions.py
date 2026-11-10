"""``/v1/suppressions``: recording a decision not to fix something.

Three endpoints and one rule that shapes all of them: a suppression changes
what a team is working on, never what the analysis found. It does not alter a
verdict, a severity, or anything the public report and badge say about
reachable code — a badge reading "none reachable" because somebody suppressed
the reachable one would be the most misleading thing this system could emit.

Every create and revoke is written to the audit log. "Who decided not to fix
this, and what did they say at the time" is the question a suppression exists
to answer later, and it cannot be answered by a row that only holds the
current state.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_api.auth import Authenticated, TenantConnection
from vexpath_api.suppress import DEFAULT_DAYS, SuppressionError, build, is_active, remaining_days
from vexpath_core.ids import new_ulid
from vexpath_db.tables import audit_log, projects, suppressions
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/v1/suppressions", tags=["suppressions"])


class SuppressionIn(BaseModel):
    """What a caller supplies to suppress a finding."""

    project: str = Field(min_length=2, max_length=100)
    advisory_id: str = Field(min_length=3, max_length=64)
    #: Required, and the API says why in the error rather than just refusing.
    reason: str = Field(min_length=1, max_length=2000)
    #: Null means every component of the project: the broader and therefore
    #: more dangerous choice, so it is never the implied one in a client.
    purl: str | None = None
    justification: str | None = None
    #: Bounded by the module, not by this field, so the limit and its reason
    #: live in one place.
    days: int = DEFAULT_DAYS


class SuppressionOut(BaseModel):
    """A suppression as the API returns it."""

    id: str
    project_id: str
    advisory_id: str
    purl: str | None
    reason: str
    justification: str | None
    expires_at: datetime
    created_at: datetime
    created_by: str | None
    revoked_at: datetime | None
    active: bool
    expires_in_days: int


@router.get("", response_model=list[SuppressionOut], summary="List suppressions")
async def list_suppressions(
    connection: TenantConnection,
    project: Annotated[str | None, Query()] = None,
    include_inactive: Annotated[bool, Query()] = False,
) -> list[SuppressionOut]:
    """Every suppression of the caller's organisation.

    Expired and revoked ones are left out by default and available on request.
    Nothing deletes them: the record of what was suppressed and why is worth
    more than a tidy table, and it is the only way to answer "how long has
    this been ignored".
    """
    query = select(suppressions).order_by(suppressions.c.created_at.desc()).limit(500)
    if project is not None:
        project_id = await _project_id(connection, project)
        query = query.where(suppressions.c.project_id == project_id)

    rows = (await connection.execute(query)).mappings()
    out = [_to_out(row) for row in rows]
    if include_inactive:
        return out
    return [row for row in out if row.active]


@router.post(
    "",
    response_model=SuppressionOut,
    status_code=status.HTTP_201_CREATED,
    summary="Suppress a finding",
)
async def create_suppression(
    payload: SuppressionIn, connection: TenantConnection, principal: Authenticated
) -> SuppressionOut:
    """Record a decision not to fix something.

    Raises:
        HTTPException: 404 if the project is not the caller's, 422 if the
            suppression is one this system will not record -- no reason, or a
            duration long enough that the expiry would be a formality.
    """
    project_id = await _project_id(connection, payload.project)
    try:
        request = build(
            advisory_id=payload.advisory_id,
            reason=payload.reason,
            days=payload.days,
            purl=payload.purl,
            justification=payload.justification,
        )
    except SuppressionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from None

    identifier = new_ulid()
    await connection.execute(
        insert(suppressions).values(
            id=identifier,
            org_id=principal.org_id,
            project_id=project_id,
            advisory_id=request.advisory_id,
            purl=request.purl,
            reason=request.reason,
            justification=request.justification,
            expires_at=request.expires_at,
            created_by=principal.actor_id,
        )
    )
    # "Who decided not to fix this, and what did they say at the time" cannot
    # be answered by a row that only holds the current state.
    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=principal.org_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            action="suppression.created",
            target_type="suppression",
            target_id=identifier,
            metadata={
                "advisory": request.advisory_id,
                "purl": request.purl,
                "reason": request.reason,
                "expires_at": request.expires_at.isoformat(),
            },
        )
    )
    log.info(
        "api.suppression.created",
        org=principal.org_id,
        advisory=request.advisory_id,
        project=payload.project,
    )
    return await _fetch(connection, identifier)


@router.delete("/{suppression_id}", response_model=SuppressionOut, summary="Revoke a suppression")
async def revoke_suppression(
    suppression_id: str, connection: TenantConnection, principal: Authenticated
) -> SuppressionOut:
    """Revoke a suppression, bringing the finding back into view.

    Marked revoked rather than deleted, so the history stays: a finding that
    was suppressed for five months and then was not is a different situation
    from one nobody ever suppressed, and only the first is worth a
    conversation.
    """
    result = await connection.execute(
        update(suppressions)
        .where((suppressions.c.id == suppression_id) & (suppressions.c.revoked_at.is_(None)))
        .values(revoked_at=_now())
        .returning(suppressions.c.id)
    )
    if result.one_or_none() is None:
        # 404 whether it belongs to someone else, does not exist, or was
        # already revoked. The caller's next step is the same in each case.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such suppression")

    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=principal.org_id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            action="suppression.revoked",
            target_type="suppression",
            target_id=suppression_id,
            metadata={},
        )
    )
    return await _fetch(connection, suppression_id)


async def _project_id(connection: AsyncConnection, slug: str) -> str:
    row = (
        await connection.execute(select(projects.c.id).where(projects.c.slug == slug))
    ).one_or_none()
    if row is None:
        # 404 for another organisation's project as well as for one that does
        # not exist: telling them apart turns this into a way of asking what a
        # competitor calls their services.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such project")
    return str(row.id)


async def _fetch(connection: AsyncConnection, identifier: str) -> SuppressionOut:
    row = (
        (await connection.execute(select(suppressions).where(suppressions.c.id == identifier)))
        .mappings()
        .one()
    )
    return _to_out(row)


def _to_out(row: Any) -> SuppressionOut:
    return SuppressionOut(
        id=row["id"],
        project_id=row["project_id"],
        advisory_id=row["advisory_id"],
        purl=row["purl"],
        reason=row["reason"],
        justification=row["justification"],
        expires_at=row["expires_at"],
        created_at=row["created_at"],
        created_by=row["created_by"],
        revoked_at=row["revoked_at"],
        active=is_active(row),
        expires_in_days=remaining_days(row),
    )


def _now() -> datetime:
    from datetime import UTC

    return datetime.now(UTC)


__all__ = ["router"]
