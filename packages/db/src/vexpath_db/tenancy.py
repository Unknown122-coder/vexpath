"""Put a request's tenant context on a database connection.

Row-level security decides what a query can see by reading a session setting.
This is the only place that setting is written, for two reasons.

**``SET`` takes no bind parameters.** Writing ``SET vexpath.org_id = '...'``
means building SQL by string concatenation out of a value that arrived in an
HTTP request, which is how a tenant identifier becomes an injection point.
``set_config`` is a function, takes a bound parameter, and cannot be escaped
out of.

**The application must not be the owner.** Policies do not apply to a
superuser or to a table's owner, and the owner is who runs migrations. So every
connection switches to a non-privileged role before it reads anything, and
that switch happens here rather than being left to each endpoint to remember.

The two contexts are deliberately separate and never both set. A tenant
context answers "what may this organisation see"; a public context answers
"what has been published". A request holding both could serve one
organisation's private findings on a public page, so entering one clears the
other.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_db.tables import APP_ROLE, ORG_SETTING, PUBLIC_SETTING

#: Switch to the non-privileged role. Done first on every connection, because
#: everything after it depends on policies actually applying.
_SET_ROLE = text(f"SET LOCAL ROLE {APP_ROLE}")

#: Written with set_config so the value is bound rather than interpolated.
#: ``true`` makes it local to the transaction, so a pooled connection cannot
#: carry one request's tenant into the next.
_SET_ORG = text(f"SELECT set_config('{ORG_SETTING}', :org_id, true)")
_SET_PUBLIC = text(f"SELECT set_config('{PUBLIC_SETTING}', :value, true)")
_CLEAR_ORG = text(f"SELECT set_config('{ORG_SETTING}', '', true)")
_CLEAR_PUBLIC = text(f"SELECT set_config('{PUBLIC_SETTING}', '', true)")


class TenancyError(Exception):
    """Raised when a context cannot be established.

    Fatal to the request. Carrying on without a tenant context would mean
    querying with no policy match, which returns nothing and looks like an
    empty account rather than a bug.
    """


@contextmanager
def tenant_context(connection: Connection, org_id: str) -> Iterator[Connection]:
    """Scope a connection to one organisation for the duration of a block.

    Raises:
        TenancyError: if the organisation identifier is empty. An empty value
            would match no rows, which is safe but indistinguishable from an
            organisation that genuinely has nothing, so it is refused instead
            of silently returning an empty account.
    """
    if not org_id or not org_id.strip():
        msg = "a tenant context needs an organisation identifier"
        raise TenancyError(msg)

    connection.execute(_SET_ROLE)
    connection.execute(_CLEAR_PUBLIC)
    connection.execute(_SET_ORG, {"org_id": org_id.strip()})
    yield connection


@contextmanager
def public_context(connection: Connection) -> Iterator[Connection]:
    """Scope a connection to what has been published.

    Only rows reachable from a project whose visibility is ``public``, and only
    the tables a report page needs. Users, API keys, policies and suppressions
    have no public policy at all, so they stay invisible here however the query
    is written.
    """
    connection.execute(_SET_ROLE)
    connection.execute(_CLEAR_ORG)
    connection.execute(_SET_PUBLIC, {"value": "on"})
    yield connection


@asynccontextmanager
async def async_tenant_context(
    connection: AsyncConnection, org_id: str
) -> AsyncIterator[AsyncConnection]:
    """The asynchronous form, which is what the API uses."""
    if not org_id or not org_id.strip():
        msg = "a tenant context needs an organisation identifier"
        raise TenancyError(msg)

    await connection.execute(_SET_ROLE)
    await connection.execute(_CLEAR_PUBLIC)
    await connection.execute(_SET_ORG, {"org_id": org_id.strip()})
    yield connection


@asynccontextmanager
async def async_public_context(connection: AsyncConnection) -> AsyncIterator[AsyncConnection]:
    """The asynchronous public read path."""
    await connection.execute(_SET_ROLE)
    await connection.execute(_CLEAR_ORG)
    await connection.execute(_SET_PUBLIC, {"value": "on"})
    yield connection


def current_org(connection: Connection) -> str:
    """Which organisation this connection is scoped to, if any.

    Exists so a test or a diagnostic endpoint can assert the context is what
    it believes, rather than inferring it from which rows came back.
    """
    result = connection.execute(
        text(f"SELECT current_setting('{ORG_SETTING}', true)")
    ).scalar_one_or_none()
    return result or ""


def is_public_context(connection: Connection) -> bool:
    result = connection.execute(
        text(f"SELECT current_setting('{PUBLIC_SETTING}', true)")
    ).scalar_one_or_none()
    return result == "on"


__all__ = [
    "TenancyError",
    "async_public_context",
    "async_tenant_context",
    "current_org",
    "is_public_context",
    "public_context",
    "tenant_context",
]
