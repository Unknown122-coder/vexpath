"""``/app/projects/{slug}/policy``: writing and trying a gate.

Two routes. The GET shows the stored expression, the presets with what each
one does, and — if the project has been scanned — what the stored expression
would have done to that scan. The POST compiles a candidate, runs it against
the same scan, and stores it only if it compiled.

The dry run is the point. A gate's mistakes are invisible in both directions:
too loose and nobody notices, too tight and the build everybody needs is red.
Running the candidate against the last real scan before saving it is the only
way to find out which one you have written.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_api import policy_pages
from vexpath_api.session import CsrfVerified, RequiredSession, SessionConnection
from vexpath_api.templating import render
from vexpath_core.ids import new_ulid
from vexpath_core.policy import DEFAULT_PRESET, PRESETS
from vexpath_db.tables import audit_log, policies, projects
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/app", tags=["dashboard"], include_in_schema=False)


@router.get("/projects/{slug:path}/policy", response_class=HTMLResponse, summary="Policy editor")
async def policy_page(
    slug: str, request: Request, session: RequiredSession, connection: SessionConnection
) -> HTMLResponse:
    """The stored policy, the presets, and a dry run of what is stored."""
    project = await _project(connection, slug)
    stored = await policy_pages.current_policy(connection, project["id"])
    expression = stored["cel"] if stored else PRESETS[DEFAULT_PRESET]

    scan = await policy_pages.latest_scan(connection, project["id"], slug)
    outcome: dict[str, Any] | None = None
    if scan is not None:
        context = await policy_pages.context_for_scan(connection, scan)
        outcome = policy_pages.dry_run(expression, context)

    return render(
        request,
        "app_policy.html",
        {
            "session": session,
            "project": project,
            "stored": stored,
            "expression": expression,
            "presets": policy_pages.preset_descriptions(),
            "default_preset": DEFAULT_PRESET,
            "scan": scan,
            "outcome": outcome,
            "problem": None,
            "saved": False,
        },
    )


@router.post(
    "/projects/{slug:path}/policy",
    response_class=HTMLResponse,
    response_model=None,
    summary="Save a policy",
)
async def save_policy(
    slug: str,
    request: Request,
    session: CsrfVerified,
    connection: SessionConnection,
    expression: Annotated[str, Form()] = "",
    action: Annotated[str, Form()] = "save",
) -> HTMLResponse:
    """Compile a candidate, try it against the last scan, and store it.

    ``action=try`` runs the dry run without storing, which is what somebody
    does four or five times before they are happy. Either way the page comes
    back with the expression still in the box: losing a half-written
    expression to a validation error is the fastest way to make somebody stop
    using an editor.
    """
    project = await _project(connection, slug)
    resolved, problem = policy_pages.check(expression)

    scan = await policy_pages.latest_scan(connection, project["id"], slug)
    outcome: dict[str, Any] | None = None
    if resolved is not None and scan is not None:
        context = await policy_pages.context_for_scan(connection, scan)
        outcome = policy_pages.dry_run(resolved, context)

    saved = False
    if resolved is not None and action == "save":
        version = await policy_pages.next_version(connection, project["id"])
        await connection.execute(
            insert(policies).values(
                id=new_ulid(),
                org_id=session.org_id,
                project_id=project["id"],
                name="dashboard",
                # The resolved expression, never the preset name: a name whose
                # meaning changed in a later release would silently change
                # what this project gates on.
                cel=resolved,
                version=version,
                source="dashboard",
            )
        )
        await connection.execute(
            insert(audit_log).values(
                id=new_ulid(),
                org_id=session.org_id,
                actor_type="user",
                actor_id=session.user_id,
                action="policy.saved",
                target_type="project",
                target_id=project["id"],
                # The expression itself, because "who loosened the gate and
                # when" is the question this log exists to answer.
                metadata={"version": version, "cel": resolved, "login": session.login},
            )
        )
        saved = True
        log.info("app.policy.saved", org=session.org_id, project=slug, version=version)

    stored = await policy_pages.current_policy(connection, project["id"])
    return render(
        request,
        "app_policy.html",
        {
            "session": session,
            "project": project,
            "stored": stored,
            # What was typed, so nothing is lost to a validation error.
            "expression": expression.strip() or (stored["cel"] if stored else ""),
            "presets": policy_pages.preset_descriptions(),
            "default_preset": DEFAULT_PRESET,
            "scan": scan,
            "outcome": outcome,
            "problem": problem,
            "saved": saved,
        },
        status_code=(status.HTTP_422_UNPROCESSABLE_CONTENT if problem else status.HTTP_200_OK),
    )


async def _project(connection: AsyncConnection, slug: str) -> dict[str, Any]:
    row = (
        (await connection.execute(select(projects).where(projects.c.slug == slug)))
        .mappings()
        .one_or_none()
    )
    if row is None:
        # 404 for another organisation's project as well as for one that does
        # not exist: the connection cannot see it either way.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such project")
    return dict(row)


__all__ = ["router"]
