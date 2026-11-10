"""Work out who is calling, and scope the database to them.

Every authenticated request does the same two things in the same order: prove
which organisation it belongs to, then put that organisation into the database
session so row-level security can act on it. Both happen here, together,
because doing the first without the second produces a request that is
authenticated and unscoped, which is the shape of a data leak.

An unauthenticated request gets no connection at all rather than an
unscoped one. There is no such thing as a query this application should run
with no tenant context, so the ability to obtain one is simply not offered.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from vexpath_api.dependencies import get_engine
from vexpath_db.tables import api_keys
from vexpath_db.tenancy import async_public_context, async_tenant_context
from vexpath_platform import apikeys
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

#: One message for every authentication failure. A caller learns the key does
#: not work, never whether it was unknown, revoked or malformed: each of those
#: would narrow a search for someone probing.
_REJECTED = "the API key is missing, malformed, unknown or revoked"


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is making this request, and on whose behalf."""

    org_id: str
    #: ``api_key`` today; ``user`` when session login lands.
    actor_type: str
    actor_id: str

    @property
    def is_api_key(self) -> bool:
        return self.actor_type == "api_key"


async def authenticate(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    engine: Annotated[AsyncEngine, Depends(get_engine)] = None,  # type: ignore[assignment]
) -> Principal:
    """Resolve an ``Authorization: Bearer`` header to an organisation.

    Raises:
        HTTPException: 401 for anything that does not resolve, with one
            message for every cause.
    """
    token = apikeys.bearer_token(authorization)
    if not token or not apikeys.looks_like_key(token):
        # Shape-checked before any lookup, which saves a round trip. It is
        # never the reason a real key is refused: a well-formed key that does
        # not exist takes the same path as one that does.
        raise _unauthorised()

    key_hash = apikeys.hash_key(token)
    async with engine.connect() as connection:
        # Read as the owner, deliberately. An API key lookup is the one query
        # that cannot be tenant-scoped, because resolving it is how the tenant
        # is discovered. It matches on the hash alone and returns one row, so
        # it cannot be steered into reading anything else.
        row = (
            await connection.execute(
                select(
                    api_keys.c.id, api_keys.c.org_id, api_keys.c.key_hash, api_keys.c.revoked_at
                ).where(api_keys.c.key_hash == key_hash)
            )
        ).one_or_none()

        stored = (
            apikeys.StoredKey(
                id=row.id, org_id=row.org_id, key_hash=row.key_hash, revoked_at=row.revoked_at
            )
            if row is not None
            else None
        )
        if not apikeys.verify(token, stored):
            log.info("api.auth.rejected", path=request.url.path)
            raise _unauthorised()
        assert stored is not None  # narrowed by verify

        await connection.execute(
            update(api_keys).where(api_keys.c.id == stored.id).values(last_used_at=apikeys.now())
        )
        await connection.commit()

    return Principal(org_id=stored.org_id, actor_type="api_key", actor_id=stored.id)


def _unauthorised() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_REJECTED,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def tenant_connection(
    principal: Annotated[Principal, Depends(authenticate)],
    engine: Annotated[AsyncEngine, Depends(get_engine)],
) -> AsyncIterator[AsyncConnection]:
    """A connection scoped to the caller's organisation.

    The only way an endpoint obtains a connection. Authentication and scoping
    are one dependency rather than two, so there is no arrangement of
    dependencies that yields an authenticated request holding an unscoped
    connection.
    """
    async with (
        engine.begin() as connection,
        async_tenant_context(connection, principal.org_id) as scoped,
    ):
        yield scoped


async def public_connection(
    engine: Annotated[AsyncEngine, Depends(get_engine)],
) -> AsyncIterator[AsyncConnection]:
    """A connection that can read only what has been published.

    Used by the report and badge pages, which have no caller to authenticate.
    It carries no tenant context, so it cannot read a private project however
    the query is written.
    """
    async with engine.begin() as connection, async_public_context(connection) as scoped:
        yield scoped


#: Annotated aliases, so an endpoint signature says which of the two it wants
#: and cannot accidentally ask for a bare engine.
Authenticated = Annotated[Principal, Depends(authenticate)]
TenantConnection = Annotated[AsyncConnection, Depends(tenant_connection)]
PublicConnection = Annotated[AsyncConnection, Depends(public_connection)]


__all__ = [
    "Authenticated",
    "Principal",
    "PublicConnection",
    "TenantConnection",
    "authenticate",
    "public_connection",
    "tenant_connection",
]
