"""Resolving a browser session, and the guards that go with it.

The JSON API authenticates a bearer key; the HTML UI authenticates a cookie.
They are kept apart on purpose and the separation is a security property worth
stating: **no endpoint accepts both.** A browser sends its cookie automatically
on any request to this origin, including one a different site caused, which is
exactly what cross-site request forgery exploits. An endpoint that accepted
either credential would inherit that problem for every caller, so ``/v1``
refuses cookies and the HTML routes refuse keys.

Three guards follow from that.

**A signed-out browser is redirected, not refused.** A 401 with a JSON body is
the correct answer to a mis-authenticated API call and a dead end for a person
who simply needs to sign in.

**Every form that changes something carries a CSRF token**, verified here
rather than in each handler. ``SameSite=Lax`` already stops the cross-site POST
and this is the second lock on the same door: a future endpoint that needs a
relaxed cookie policy must not silently lose the only defence.

**The session's organisation is put into the database session**, by the same
dependency that resolved the cookie, for the same reason the API key path does
it: authentication without scoping produces a request that is authenticated and
unscoped, which is the shape of a data leak.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated

from fastapi import Depends, Request, Response
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from vexpath_api.dependencies import get_engine, get_settings_from_app
from vexpath_api.oauth import Identity
from vexpath_core.ids import new_ulid
from vexpath_db.tables import orgs, sessions, users, users_orgs
from vexpath_db.tenancy import async_tenant_context
from vexpath_platform import sessions as tokens
from vexpath_platform.logging import get_logger
from vexpath_platform.settings import Settings

log = get_logger(__name__)

#: Where a signed-out browser is sent, and where a sign-in returns to by
#: default.
LOGIN_PATH = "/login"
HOME_PATH = "/app"

#: The form field carrying the CSRF token. One name everywhere, because a
#: template that spells it differently produces a form that always fails, and
#: the failure looks like a session problem.
CSRF_FIELD = "csrf_token"


class RedirectRequired(Exception):  # noqa: N818
    """Raised to send a browser somewhere else.

    An exception rather than a return value so a dependency can do it: the
    guard that discovers a signed-out browser is not the code that renders the
    page, and threading a redirect back through every handler would mean every
    handler could forget it.
    """

    def __init__(self, location: str, *, status_code: int = 303) -> None:
        self.location = location
        self.status_code = status_code
        super().__init__(location)


@dataclass(frozen=True, slots=True)
class SessionPrincipal:
    """Who is viewing a page, and on whose behalf.

    Carries the organisation's name and slug because every page shows them,
    and fetching them again in each handler would be a second query for
    something the session lookup already joined.
    """

    session_id: str
    user_id: str
    org_id: str
    login: str
    email: str | None
    org_slug: str
    org_name: str
    role: str
    expires_at: datetime
    csrf_token: str

    @property
    def is_owner(self) -> bool:
        return self.role == "owner"


async def resolve_session(
    request: Request,
    engine: Annotated[AsyncEngine, Depends(get_engine)],
    settings: Annotated[Settings, Depends(get_settings_from_app)],
) -> SessionPrincipal | None:
    """The session behind the cookie, or None.

    Read on the owner's connection, deliberately, for the same reason the API
    key lookup is: resolving the credential is how the organisation is
    discovered, so it cannot itself be organisation-scoped. It matches on the
    token hash alone and returns one row, so it cannot be steered into reading
    anything else.
    """
    presented = request.cookies.get(tokens.COOKIE_NAME)
    if not presented:
        return None

    token_hash = tokens.hash_token(presented)
    async with engine.connect() as connection:
        row = (
            await connection.execute(
                select(
                    sessions.c.id,
                    sessions.c.user_id,
                    sessions.c.org_id,
                    sessions.c.token_hash,
                    sessions.c.expires_at,
                    sessions.c.revoked_at,
                    users.c.login,
                    users.c.email,
                    orgs.c.slug,
                    orgs.c.name,
                )
                .join(users, users.c.id == sessions.c.user_id)
                .join(orgs, orgs.c.id == sessions.c.org_id)
                .where(sessions.c.token_hash == token_hash)
            )
        ).one_or_none()

        stored = row.token_hash if row is not None else None
        if not tokens.verify_token(presented, stored):
            return None
        assert row is not None  # narrowed by verify_token

        if row.revoked_at is not None or tokens.is_expired(row.expires_at):
            # Checked in the application as well as being enforced by
            # deletion: the cleanup is a background job, and a job that has
            # not run yet must not mean an immortal session.
            return None

        role = (
            await connection.execute(
                select(users_orgs.c.role).where(
                    (users_orgs.c.user_id == row.user_id) & (users_orgs.c.org_id == row.org_id)
                )
            )
        ).scalar_one_or_none()
        if role is None:
            # Membership was removed while the session lived. The cookie is
            # valid and means nothing, which is the correct outcome: being
            # taken off a team should end access without waiting for an
            # expiry.
            return None

        await connection.execute(
            update(sessions).where(sessions.c.id == row.id).values(last_seen_at=tokens.now())
        )
        await connection.commit()

    return SessionPrincipal(
        session_id=row.id,
        user_id=row.user_id,
        org_id=row.org_id,
        login=row.login,
        email=row.email,
        org_slug=row.slug,
        org_name=row.name,
        role=str(role),
        expires_at=row.expires_at,
        csrf_token=tokens.csrf_token(settings.secret_key, row.id),
    )


async def require_session(
    request: Request,
    principal: Annotated[SessionPrincipal | None, Depends(resolve_session)],
) -> SessionPrincipal:
    """The session, or a redirect to the sign-in page.

    The page the browser was trying to reach travels in the query string so
    signing in returns there, which is the difference between a sign-in that
    resumes what somebody was doing and one that dumps them on a dashboard.
    """
    if principal is None:
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"
        raise RedirectRequired(f"{LOGIN_PATH}?next={_quote(target)}")
    return principal


async def require_csrf(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(require_session)],
) -> SessionPrincipal:
    """Verify the CSRF token on a form submission.

    A missing token fails. A form that forgot to carry one must break loudly
    in development rather than pass by default, which is the difference
    between a check and a decoration.
    """
    form = await request.form()
    presented = form.get(CSRF_FIELD)
    # The application's own settings, not the process cache: the two are the
    # same object in a deployment and different ones in a test, and a token
    # verified under a different key than it was signed with would fail for a
    # reason nobody could find.
    settings = get_settings_from_app(request)
    if not isinstance(presented, str) or not tokens.verify_csrf(
        settings.secret_key, principal.session_id, presented
    ):
        log.warning("api.csrf.rejected", path=request.url.path, user=principal.user_id)
        # Sent back to the page rather than answered with a bare 403: the
        # honest cause is almost always a session that expired in another tab,
        # and the remedy is to load the form again.
        raise RedirectRequired(f"{LOGIN_PATH}?next={_quote(request.url.path)}")
    return principal


async def session_connection(
    principal: Annotated[SessionPrincipal, Depends(require_session)],
    engine: Annotated[AsyncEngine, Depends(get_engine)],
) -> AsyncIterator[AsyncConnection]:
    """A connection scoped to the signed-in user's organisation.

    The only way an HTML handler obtains a connection, so there is no
    arrangement of dependencies that yields a signed-in request holding an
    unscoped one.
    """
    async with (
        engine.begin() as connection,
        async_tenant_context(connection, principal.org_id) as scoped,
    ):
        yield scoped


# --- Establishing a session -------------------------------------------------


async def sign_in(
    connection: AsyncConnection, identity: Identity, *, provider: str
) -> tuple[str, str]:
    """Find or create the account behind an identity, and its organisation.

    Returns the user and organisation identifiers.

    Keyed on ``(provider, subject)`` and never on the login. A GitHub login can
    be renamed and the old name claimed by somebody else, so keying on it would
    eventually sign one person into another person's account -- the single
    worst thing an identity layer can do.

    Run on the owner's connection: there is no organisation in scope yet, and
    discovering which one applies is the purpose of this call.
    """
    existing = (
        await connection.execute(
            select(users.c.id, users.c.org_id).where(
                (users.c.provider == provider) & (users.c.provider_subject == identity.subject)
            )
        )
    ).one_or_none()

    if existing is not None:
        # The login and email are display values and are refreshed on every
        # sign-in: a renamed account should show its new name, and the subject
        # is what kept the identity stable across the rename.
        await connection.execute(
            update(users)
            .where(users.c.id == existing.id)
            .values(login=identity.login, email=identity.email, last_seen_at=tokens.now())
        )
        return str(existing.id), str(existing.org_id)

    org_id = new_ulid()
    user_id = new_ulid()
    slug = await _available_slug(connection, identity.login)

    await connection.execute(
        insert(orgs).values(
            id=org_id,
            org_id=org_id,
            slug=slug,
            name=identity.name or identity.login,
        )
    )
    await connection.execute(
        insert(users).values(
            id=user_id,
            org_id=org_id,
            provider=provider,
            provider_subject=identity.subject,
            login=identity.login,
            email=identity.email,
            last_seen_at=tokens.now(),
        )
    )
    # Owner, because they created it. The first member of a new organisation
    # being a plain member would leave it with nobody able to administer it.
    await connection.execute(
        insert(users_orgs).values(id=new_ulid(), org_id=org_id, user_id=user_id, role="owner")
    )
    log.info("api.signin.created_org", org=org_id, slug=slug, provider=provider)
    return user_id, org_id


async def _available_slug(connection: AsyncConnection, login: str) -> str:
    """A URL-safe organisation slug derived from the login.

    The slug appears in every public report URL, so it is normalised rather
    than trusted: a GitHub login is restricted enough to be mostly safe, and
    "mostly" is not a basis for putting a value in a path.
    """
    base = "".join(character if character.isalnum() else "-" for character in login.lower())
    base = "-".join(part for part in base.split("-") if part) or "org"
    base = base[:40]

    candidate = base
    for suffix in range(1, 50):
        taken = (
            await connection.execute(select(orgs.c.id).where(orgs.c.slug == candidate))
        ).scalar_one_or_none()
        if taken is None:
            return candidate
        candidate = f"{base}-{suffix}"
    # Fifty collisions means something is wrong with the derivation rather
    # than with this login, and a random suffix beats failing a sign-in.
    return f"{base}-{new_ulid()[-6:].lower()}"


async def create_session(connection: AsyncConnection, *, user_id: str, org_id: str) -> str:
    """Issue a session and store its hash. Returns the cookie value.

    The secret is returned and never stored, which is the whole arrangement:
    what the database holds cannot be presented as a credential.
    """
    issued = tokens.issue()
    await connection.execute(
        insert(sessions).values(
            id=new_ulid(),
            org_id=org_id,
            user_id=user_id,
            token_hash=issued.token_hash,
            expires_at=issued.expires_at,
            last_seen_at=tokens.now(),
        )
    )
    return issued.secret


async def revoke_session(connection: AsyncConnection, session_id: str) -> None:
    """End one session.

    Deleted rather than marked revoked. A signed-out session has no history
    worth keeping, and a row that lingers is a row that can be resurrected by
    a bug in a query that forgets the condition.
    """
    await connection.execute(sessions.delete().where(sessions.c.id == session_id))


def set_session_cookie(response: Response, secret: str, settings: Settings) -> None:
    """Attach the session cookie to a response."""
    response.set_cookie(
        tokens.COOKIE_NAME,
        secret,
        **tokens.cookie_attributes(secure=settings.cookies_require_https),  # type: ignore[arg-type]
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    """Remove the session cookie.

    The attributes must match the ones it was set with, or the browser keeps
    the original and a sign-out silently does nothing.
    """
    response.delete_cookie(
        tokens.COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.cookies_require_https,
    )


def _quote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


def safe_return_path(candidate: str | None) -> str:
    """A path to redirect to after sign-in, or the dashboard.

    Anything that is not a single-slash-rooted local path is discarded. A
    value arriving in a query string and used in a ``Location`` header is an
    open redirect, which is the mechanism behind every "you were signed out,
    sign in again" phishing page: the link really does point at this site, and
    the destination really is attacker-chosen.
    """
    if not candidate or not candidate.startswith("/"):
        return HOME_PATH
    # "//evil.example" is a protocol-relative URL, not a local path, and
    # browsers follow it off-site.
    if candidate.startswith("//") or candidate.startswith("/\\"):
        return HOME_PATH
    return candidate


#: Annotated aliases, so a handler signature says which guard it wants.
CurrentSession = Annotated[SessionPrincipal | None, Depends(resolve_session)]
RequiredSession = Annotated[SessionPrincipal, Depends(require_session)]
CsrfVerified = Annotated[SessionPrincipal, Depends(require_csrf)]
SessionConnection = Annotated[AsyncConnection, Depends(session_connection)]


__all__ = [
    "CSRF_FIELD",
    "HOME_PATH",
    "LOGIN_PATH",
    "CsrfVerified",
    "CurrentSession",
    "RedirectRequired",
    "RequiredSession",
    "SessionConnection",
    "SessionPrincipal",
    "clear_session_cookie",
    "create_session",
    "require_csrf",
    "require_session",
    "resolve_session",
    "revoke_session",
    "safe_return_path",
    "session_connection",
    "set_session_cookie",
    "sign_in",
]
