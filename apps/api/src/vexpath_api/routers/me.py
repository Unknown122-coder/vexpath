"""Who am I: the endpoint a credential is checked against.

Exists so that ``vexpath login`` can verify a key before storing it. A tool
that stores an unverified credential turns a typo into an authentication
failure on some later command, with nothing to connect the two.

It returns the organisation and what the key may do, and never the key.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from vexpath_api.auth import Authenticated, TenantConnection
from vexpath_db.tables import orgs, projects

router = APIRouter(prefix="/v1", tags=["identity"])


class WhoAmI(BaseModel):
    """What a caller is told about their own credential."""

    org_id: str
    org_slug: str
    org_name: str
    actor_type: str
    #: The key's own identifier, so a dashboard listing can be matched against
    #: the key actually in use. Not the secret, which the server does not have.
    actor_id: str
    project_count: int


@router.get("/me", response_model=WhoAmI, summary="Describe the current credential")
async def whoami(connection: TenantConnection, principal: Authenticated) -> WhoAmI:
    """Describe the organisation this credential belongs to.

    Reaching this endpoint at all is the proof the credential works, which is
    what makes it the right thing for ``vexpath login`` to call.
    """
    org = (
        (await connection.execute(select(orgs).where(orgs.c.id == principal.org_id)))
        .mappings()
        .one()
    )
    count = (await connection.execute(select(func.count()).select_from(projects))).scalar_one()

    return WhoAmI(
        org_id=org["id"],
        org_slug=org["slug"],
        org_name=org["name"],
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        project_count=int(count or 0),
    )


__all__ = ["router"]
