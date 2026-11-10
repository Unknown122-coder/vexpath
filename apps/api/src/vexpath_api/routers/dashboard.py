"""The signed-in pages: projects, publishing, and API keys.

Everything here is a plain form submission. Not "works without JavaScript as a
fallback" -- there is no JavaScript to fall back from. Each action is a `POST`
to its own URL that answers with a redirect, which is the pattern the web has
had since forms existed and the one that still works in a text browser, with a
screen reader, on a train, and under a content-security policy that forbids
script.

Three decisions worth stating.

**A new key's secret is shown once, on the page that created it.** Not
redirected to, because a redirect would have to carry the secret in a URL
where it would land in history, in logs and in a `Referer` header. The page
says plainly that it will not be shown again, which is true: only the hash is
stored.

**Publishing is its own form with its own button.** The one setting whose
effect is visible to the entire internet should not be a checkbox somebody
changes while editing a repository URL.

**Every form carries a CSRF token, verified by the dependency rather than the
handler.** A handler that had to remember would eventually be written by
somebody in a hurry.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_api.session import (
    CsrfVerified,
    RequiredSession,
    SessionConnection,
)
from vexpath_api.templating import render
from vexpath_core.ids import new_ulid
from vexpath_db.tables import api_keys, audit_log, findings, projects, scans
from vexpath_platform import apikeys
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/app", tags=["dashboard"], include_in_schema=False)

#: The same vocabulary the JSON API enforces. A slug appears in a public
#: report URL and in a badge path, so anything outside this set would have to
#: be escaped in several places and one of them would eventually be missed.
SLUG_CHARACTERS = set("abcdefghijklmnopqrstuvwxyz0123456789._/-")


@router.get("", response_class=HTMLResponse, summary="Dashboard")
async def overview(
    request: Request, session: RequiredSession, connection: SessionConnection
) -> HTMLResponse:
    """Projects, with what the latest scan of each found.

    One query with the counts in it. A list that fetched each project's latest
    scan separately would be fine with three projects and unusable with
    three hundred.
    """
    rows = (
        await connection.execute(
            select(
                projects.c.id,
                projects.c.slug,
                projects.c.repo_url,
                projects.c.visibility,
                projects.c.created_at,
                func.count(scans.c.id).label("scan_count"),
                func.max(scans.c.created_at).label("last_scan_at"),
            )
            .outerjoin(scans, scans.c.project_id == projects.c.id)
            .group_by(projects.c.id)
            .order_by(projects.c.slug)
            .limit(200)
        )
    ).mappings()
    project_rows = [dict(row) for row in rows]

    latest = await _latest_summaries(connection, [row["id"] for row in project_rows])
    for row in project_rows:
        row["latest"] = latest.get(row["id"])

    return render(
        request,
        "app_overview.html",
        {"session": session, "projects": project_rows, "error": None},
    )


async def _latest_summaries(
    connection: AsyncConnection, project_ids: list[str]
) -> dict[str, dict[str, Any]]:
    """The most recent scan of each project, with its finding counts.

    Returns an empty mapping for an organisation with no scans, which is the
    ordinary state of a new account and must render as "nothing scanned yet"
    rather than as an error.
    """
    if not project_ids:
        return {}

    newest = (
        select(scans.c.project_id, func.max(scans.c.created_at).label("created_at"))
        .where(scans.c.project_id.in_(project_ids))
        .group_by(scans.c.project_id)
        .subquery()
    )
    rows = (
        await connection.execute(
            select(
                scans.c.id,
                scans.c.project_id,
                scans.c.created_at,
                scans.c.summary,
                scans.c.status,
                scans.c.git_ref,
                func.count(findings.c.id).label("finding_count"),
            )
            .join(
                newest,
                (newest.c.project_id == scans.c.project_id)
                & (newest.c.created_at == scans.c.created_at),
            )
            .outerjoin(findings, findings.c.scan_id == scans.c.id)
            .group_by(scans.c.id)
        )
    ).mappings()
    return {row["project_id"]: dict(row) for row in rows}


# response_model=None: the handler answers with a redirect on success and
# with the re-rendered page on a bad name, and FastAPI cannot build a
# response model from a union of responses.
@router.post("/projects", response_model=None, summary="Create a project")
async def create_project(
    request: Request,
    session: CsrfVerified,
    connection: SessionConnection,
    slug: Annotated[str, Form()],
    repo_url: Annotated[str, Form()] = "",
) -> HTMLResponse | RedirectResponse:
    """Create a project from the dashboard form.

    The organisation comes from the session, never from the form. A field that
    named it could be edited to create a project inside somebody else's
    organisation, and the row-level security policy would then let them read
    it back quite correctly.
    """
    candidate = slug.strip().lower()
    problem = _slug_problem(candidate)
    if problem is None:
        taken = (
            await connection.execute(select(projects.c.id).where(projects.c.slug == candidate))
        ).one_or_none()
        if taken is not None:
            problem = f"there is already a project called {candidate!r}"

    if problem is not None:
        # Re-rendered with the message rather than redirected to an error
        # page, so what was typed is still on the screen.
        return await _overview_with_error(request, session, connection, problem)

    await connection.execute(
        insert(projects).values(
            id=new_ulid(),
            org_id=session.org_id,
            slug=candidate,
            repo_url=repo_url.strip() or None,
            # Private. A default of public would publish a dependency
            # inventory because somebody did not read a field, and an
            # inventory is a map of where a company is behind on patches.
            visibility="private",
            entry_points=[],
            settings={},
        )
    )
    log.info("app.project.created", org=session.org_id, slug=candidate)
    return RedirectResponse("/app", status_code=status.HTTP_303_SEE_OTHER)


def _slug_problem(candidate: str) -> str | None:
    """Why this slug is unacceptable, or None.

    Returned as a sentence for the person rather than as a pattern. "Must
    match ^[a-z0-9][a-z0-9._/-]{0,98}[a-z0-9]$" is accurate and tells nobody
    what to type.
    """
    if len(candidate) < 2:
        return "a project name needs at least two characters"
    if len(candidate) > 100:
        return "a project name can be at most 100 characters"
    if not candidate[0].isalnum() or not candidate[-1].isalnum():
        return "a project name has to start and end with a letter or a number"
    extra = set(candidate) - SLUG_CHARACTERS
    if extra:
        return (
            "a project name can hold lower-case letters, numbers, and the "
            f"characters . _ - / -- not {''.join(sorted(extra))!r}"
        )
    return None


async def _overview_with_error(
    request: Request, session: Any, connection: AsyncConnection, message: str
) -> HTMLResponse:
    rows = (
        await connection.execute(
            select(
                projects.c.id,
                projects.c.slug,
                projects.c.repo_url,
                projects.c.visibility,
                projects.c.created_at,
                func.count(scans.c.id).label("scan_count"),
                func.max(scans.c.created_at).label("last_scan_at"),
            )
            .outerjoin(scans, scans.c.project_id == projects.c.id)
            .group_by(projects.c.id)
            .order_by(projects.c.slug)
            .limit(200)
        )
    ).mappings()
    project_rows = [dict(row) for row in rows]
    for row in project_rows:
        row["latest"] = None
    return render(
        request,
        "app_overview.html",
        {"session": session, "projects": project_rows, "error": message},
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
    )


@router.post("/projects/{slug:path}/visibility", summary="Publish or unpublish a project")
async def set_visibility(
    slug: str,
    session: CsrfVerified,
    connection: SessionConnection,
    visibility: Annotated[str, Form()],
) -> RedirectResponse:
    """Publish or unpublish one project's reports.

    Its own form and its own route, because this is the only setting here
    whose effect is visible to everyone, and it should take a deliberate click
    rather than ride along with an unrelated save.
    """
    if visibility not in {"private", "public"}:
        return RedirectResponse("/app", status_code=status.HTTP_303_SEE_OTHER)

    await connection.execute(
        update(projects).where(projects.c.slug == slug).values(visibility=visibility)
    )
    # Recorded, because publishing a dependency inventory is the single most
    # consequential thing anybody does on this screen, and "who published
    # this" must be answerable afterwards.
    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=session.org_id,
            actor_type="user",
            actor_id=session.user_id,
            action=f"project.visibility.{visibility}",
            target_type="project",
            target_id=slug,
            metadata={"login": session.login},
        )
    )
    log.info("app.project.visibility", org=session.org_id, slug=slug, visibility=visibility)
    return RedirectResponse("/app", status_code=status.HTTP_303_SEE_OTHER)


# --- API keys ---------------------------------------------------------------


@router.get("/keys", response_class=HTMLResponse, summary="API keys")
async def keys_page(
    request: Request, session: RequiredSession, connection: SessionConnection
) -> HTMLResponse:
    """The organisation's API keys.

    Shows the prefix, who created it and when it was last used. Never the
    secret: there is nothing stored that could show it.
    """
    return render(
        request,
        "app_keys.html",
        {
            "session": session,
            "keys": await _keys(connection),
            "issued": None,
            "error": None,
        },
    )


@router.post("/keys", response_class=HTMLResponse, summary="Create an API key")
async def create_key(
    request: Request,
    session: CsrfVerified,
    connection: SessionConnection,
    name: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Issue a key and show the secret once.

    Answers with the page rather than a redirect, deliberately. A redirect
    would have to carry the secret in the URL, where it would be written into
    browser history, into any proxy log on the way, and into the ``Referer``
    header of the next request. The secret exists in this one response and
    nowhere else, which is also why the page says so in as many words.
    """
    label = name.strip() or "default"
    if len(label) > 100:
        label = label[:100]

    issued = apikeys.issue()
    key_id = new_ulid()
    await connection.execute(
        insert(api_keys).values(
            id=key_id,
            org_id=session.org_id,
            name=label,
            key_hash=issued.key_hash,
            prefix=issued.prefix,
            created_by=session.user_id,
        )
    )
    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=session.org_id,
            actor_type="user",
            actor_id=session.user_id,
            action="api_key.created",
            target_type="api_key",
            target_id=key_id,
            metadata={"name": label, "prefix": issued.prefix},
        )
    )
    log.info("app.key.created", org=session.org_id, key=key_id)

    return render(
        request,
        "app_keys.html",
        {
            "session": session,
            "keys": await _keys(connection),
            # The only moment this value is ever rendered.
            "issued": {"secret": issued.secret, "name": label},
            "error": None,
        },
        status_code=status.HTTP_201_CREATED,
    )


@router.post("/keys/{key_id}/revoke", summary="Revoke an API key")
async def revoke_key(
    key_id: str, session: CsrfVerified, connection: SessionConnection
) -> RedirectResponse:
    """Revoke a key.

    Marked revoked rather than deleted: the audit log refers to it, and a
    revoked key that vanished would leave entries pointing at nothing. The
    authentication path checks ``revoked_at``, so a revoked key stops working
    immediately.
    """
    await connection.execute(
        update(api_keys)
        .where((api_keys.c.id == key_id) & (api_keys.c.revoked_at.is_(None)))
        .values(revoked_at=apikeys.now())
    )
    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=session.org_id,
            actor_type="user",
            actor_id=session.user_id,
            action="api_key.revoked",
            target_type="api_key",
            target_id=key_id,
            metadata={"login": session.login},
        )
    )
    log.info("app.key.revoked", org=session.org_id, key=key_id)
    return RedirectResponse("/app/keys", status_code=status.HTTP_303_SEE_OTHER)


async def _keys(connection: AsyncConnection) -> list[dict[str, Any]]:
    rows = (
        await connection.execute(
            select(
                api_keys.c.id,
                api_keys.c.name,
                api_keys.c.prefix,
                api_keys.c.created_at,
                api_keys.c.last_used_at,
                api_keys.c.revoked_at,
            ).order_by(api_keys.c.created_at.desc())
        )
    ).mappings()
    return [dict(row) for row in rows]


__all__ = ["SLUG_CHARACTERS", "router"]
