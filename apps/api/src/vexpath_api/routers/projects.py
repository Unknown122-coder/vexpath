"""Projects: the thing scans belong to.

A project is a repository the platform tracks. It carries the entry points and
settings a scan uses, and the one flag that decides whether its reports are
published.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, insert, select, update

from vexpath_api.auth import Authenticated, TenantConnection
from vexpath_core.ids import new_ulid
from vexpath_db.tables import projects, scans

router = APIRouter(prefix="/v1/projects", tags=["projects"])

#: Slugs are used in URLs and in badge paths, so the vocabulary is narrow on
#: purpose: anything else would have to be escaped in several places, and one
#: of them would eventually be missed.
_SLUG_PATTERN = r"^[a-z0-9][a-z0-9._/-]{0,98}[a-z0-9]$"


class ProjectIn(BaseModel):
    """What a caller supplies to create or update a project."""

    slug: str = Field(min_length=2, max_length=100, pattern=_SLUG_PATTERN)
    repo_url: str | None = None
    default_branch: str = "main"
    #: Private unless asked otherwise. A default of public would publish a
    #: dependency inventory because somebody did not read a field.
    visibility: str = "private"
    entry_points: list[str] = Field(default_factory=list)
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("visibility")
    @classmethod
    def _known_visibility(cls, value: str) -> str:
        if value not in {"private", "public"}:
            msg = "visibility must be 'private' or 'public'"
            raise ValueError(msg)
        return value

    @field_validator("repo_url")
    @classmethod
    def _plausible_repo(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        if not value.startswith(("https://", "git@")):
            msg = "repo_url should be an https:// or git@ URL"
            raise ValueError(msg)
        return value.strip()


class ProjectOut(BaseModel):
    """A project as the API returns it."""

    id: str
    slug: str
    repo_url: str | None
    default_branch: str
    visibility: str
    entry_points: list[str]
    settings: dict[str, Any]
    created_at: datetime
    scan_count: int = 0
    latest_scan_id: str | None = None


@router.get("", response_model=list[ProjectOut], summary="List projects")
async def list_projects(
    connection: TenantConnection,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ProjectOut]:
    """Every project of the caller's organisation.

    No organisation filter in the query: row-level security applies it, and
    adding one here would suggest the filter is this endpoint's job rather
    than the database's.
    """
    rows = (
        await connection.execute(
            select(
                projects,
                func.count(scans.c.id).label("scan_count"),
                func.max(scans.c.id).label("latest_scan_id"),
            )
            .outerjoin(scans, scans.c.project_id == projects.c.id)
            .group_by(projects.c.id)
            .order_by(projects.c.slug)
            .limit(limit)
        )
    ).mappings()
    return [_to_out(row) for row in rows]


@router.post(
    "",
    response_model=ProjectOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a project",
)
async def create_project(
    payload: ProjectIn, connection: TenantConnection, principal: Authenticated
) -> ProjectOut:
    """Create a project.

    The organisation comes from the credential, never from the request body. A
    caller who could name the organisation could create a project inside
    someone else's, and the row-level security policy would then happily let
    them read it back.
    """
    existing = (
        await connection.execute(select(projects.c.id).where(projects.c.slug == payload.slug))
    ).one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"a project with slug {payload.slug!r} already exists",
        )

    identifier = new_ulid()
    await connection.execute(
        insert(projects).values(
            id=identifier,
            org_id=principal.org_id,
            slug=payload.slug,
            repo_url=payload.repo_url,
            default_branch=payload.default_branch,
            visibility=payload.visibility,
            entry_points=payload.entry_points,
            settings=payload.settings,
        )
    )
    return await _fetch(connection, identifier)


class PolicyOut(BaseModel):
    """The policy a project is governed by."""

    name: str
    #: The expression itself, so a caller can evaluate it locally and get the
    #: same answer the server would. A preset name resolves to its expression
    #: before it leaves here: the client must not have to know the
    #: vocabulary, and a preset that changes meaning in a later release must
    #: not silently change what a stored policy does.
    expression: str
    version: int
    source: str | None = None
    created_at: datetime


# Registered before the ``{slug:path}`` route below, which would otherwise
# match "myproject/policy" as a slug -- ``:path`` matches slashes, so the
# more specific route has to be declared first. The visibility route after
# it escapes the problem only because it is a PUT.
@router.get(
    "/{slug:path}/policy",
    response_model=PolicyOut,
    summary="Read the policy that governs a project",
)
async def read_policy(slug: str, connection: TenantConnection) -> PolicyOut:
    """The project's current policy, so a build can apply the same rule.

    Exists so that a policy configured once in the dashboard governs every
    scan, rather than depending on each caller passing the right ``--policy``
    flag. ``vexpath scan --policy project`` reads this.

    Raises:
        HTTPException: 404 if the project does not exist for this
            organisation, or if it has no policy. Those are deliberately the
            same answer: a project with no policy has nothing to apply, and
            the caller's next move is identical either way.
    """
    from vexpath_api.policy_pages import current_policy
    from vexpath_core.policy import PRESETS

    project = (
        (await connection.execute(select(projects).where(projects.c.slug == slug)))
        .mappings()
        .one_or_none()
    )
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such project")

    stored = await current_policy(connection, project["id"])
    if stored is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"project {slug!r} has no policy. Set one in the dashboard.",
        )

    return PolicyOut(
        name=stored["name"],
        expression=PRESETS.get(stored["cel"].strip(), stored["cel"]),
        version=stored["version"],
        source=stored["source"],
        created_at=stored["created_at"],
    )


@router.get("/{slug:path}", response_model=ProjectOut, summary="Read one project")
async def read_project(slug: str, connection: TenantConnection) -> ProjectOut:
    row = (
        (await connection.execute(select(projects).where(projects.c.slug == slug)))
        .mappings()
        .one_or_none()
    )
    if row is None:
        # 404 whether the project belongs to someone else or does not exist.
        # Distinguishing them would turn this endpoint into a way of asking
        # whether another organisation has a project by that name.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such project")
    return await _fetch(connection, row["id"])


class VisibilityIn(BaseModel):
    visibility: str

    @field_validator("visibility")
    @classmethod
    def _known(cls, value: str) -> str:
        if value not in {"private", "public"}:
            msg = "visibility must be 'private' or 'public'"
            raise ValueError(msg)
        return value


@router.put("/{slug:path}/visibility", response_model=ProjectOut, summary="Publish or unpublish")
async def set_visibility(
    slug: str, payload: VisibilityIn, connection: TenantConnection
) -> ProjectOut:
    """Change whether a project's reports are published.

    Its own endpoint rather than a field on a general update, because this is
    the one setting whose effect is visible to the entire internet, and it
    should be hard to change by accident while editing something else.
    """
    result = await connection.execute(
        update(projects)
        .where(projects.c.slug == slug)
        .values(visibility=payload.visibility)
        .returning(projects.c.id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such project")
    return await _fetch(connection, row.id)


async def _fetch(connection: Any, identifier: str) -> ProjectOut:
    row = (
        (
            await connection.execute(
                select(
                    projects,
                    func.count(scans.c.id).label("scan_count"),
                    func.max(scans.c.id).label("latest_scan_id"),
                )
                .outerjoin(scans, scans.c.project_id == projects.c.id)
                .where(projects.c.id == identifier)
                .group_by(projects.c.id)
            )
        )
        .mappings()
        .one()
    )
    return _to_out(row)


def _to_out(row: Any) -> ProjectOut:
    return ProjectOut(
        id=row["id"],
        slug=row["slug"],
        repo_url=row["repo_url"],
        default_branch=row["default_branch"],
        visibility=row["visibility"],
        entry_points=list(row["entry_points"] or []),
        settings=dict(row["settings"] or {}),
        created_at=row["created_at"],
        scan_count=int(row.get("scan_count") or 0),
        latest_scan_id=row.get("latest_scan_id"),
    )


__all__ = ["router"]
