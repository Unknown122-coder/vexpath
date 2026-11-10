"""Scan upload: how a CI job gets its conclusions onto the platform.

The CLI does the analysis and uploads the result. The server does not re-run
it, and that is a deliberate choice with a consequence worth stating plainly:
an uploaded result is something the client asserts. The threat model calls it
"self-reported" until an attestation is verified against a transparency log,
and the report page says so.

What the server does do is refuse to store anything it cannot make sense of.
The uploaded document is validated against the same model the analysis
produced, so a malformed or hand-edited result is rejected at the boundary
rather than becoming rows nothing can interpret.

The ingest is one transaction. A half-stored scan would show a project with
findings whose evidence is missing, which reads as "nothing to see here"
rather than as a broken upload.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_api.auth import Authenticated, TenantConnection
from vexpath_api.dependencies import get_engine, get_settings_from_app
from vexpath_api.webhooks import dispatch
from vexpath_core.enums import Verdict
from vexpath_core.ids import new_ulid
from vexpath_core.models.results import ScanResults
from vexpath_db.tables import (
    audit_log,
    components,
    findings,
    policy_evaluations,
    projects,
    reachability_results,
    sboms,
    scans,
)
from vexpath_platform.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/v1/scans", tags=["scans"])

#: Refuse an upload larger than this. A result document for a project with ten
#: thousand dependencies is a few megabytes; an order of magnitude more is
#: either a mistake or an attempt to fill the disk.
MAX_FINDINGS = 50_000


class ScanUpload(BaseModel):
    """What the CLI posts after a scan."""

    project: str = Field(min_length=2, max_length=100)
    #: The scan's own output, exactly as ``vexpath scan --format json`` wrote
    #: it. Validated through the same model, so the server and the client
    #: cannot disagree about what a verdict means.
    results: dict[str, Any]


class ScanOut(BaseModel):
    """A stored scan."""

    id: str
    project_id: str
    mode: str
    git_ref: str | None
    git_sha: str | None
    advisory_snapshot_id: str | None
    core_version: str
    status: str
    summary: dict[str, Any]
    created_at: datetime
    finding_count: int = 0


@router.post(
    "", response_model=ScanOut, status_code=status.HTTP_201_CREATED, summary="Upload a scan"
)
async def upload_scan(
    payload: ScanUpload,
    request: Request,
    background: BackgroundTasks,
    connection: TenantConnection,
    principal: Authenticated,
) -> ScanOut:
    """Store the result of a scan run elsewhere.

    Raises:
        HTTPException: 404 if the project does not exist for this
            organisation, 422 if the results document is not one this build
            understands, 413 if it is implausibly large.
    """
    try:
        results = ScanResults.model_validate(payload.results)
    except ValidationError as exc:
        # The document is rejected rather than partially stored: a result the
        # server cannot interpret would become rows nothing can read back.
        #
        # Raised without chaining the validation error. An exception whose
        # cause crosses the middleware stack is re-raised by it rather than
        # becoming a response, so the client would get a 500 for what is
        # plainly their mistake. The detail below carries what they need, and
        # the full error goes to the log.
        log.info(
            "api.scan.rejected",
            project=payload.project,
            problems=exc.error_count(),
            detail=exc.errors(include_url=False)[:5],
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "message": "the results document is not one this build understands",
                "problems": exc.error_count(),
                # The first few, named. A client fixing their upload needs to
                # know which field, not only that something was wrong.
                "fields": [
                    ".".join(str(part) for part in error["loc"]) or "(root)"
                    for error in exc.errors(include_url=False)[:5]
                ],
            },
        ) from None

    if len(results.findings) > MAX_FINDINGS:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"{len(results.findings)} findings is above the {MAX_FINDINGS} limit",
        )

    project = (
        (await connection.execute(select(projects).where(projects.c.slug == payload.project)))
        .mappings()
        .one_or_none()
    )
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no project {payload.project!r} in this organisation",
        )

    scan_id = new_ulid()
    await _store(connection, scan_id, project, results, principal.org_id, principal.actor_id)

    log.info(
        "api.scan.ingested",
        scan_id=scan_id,
        project=payload.project,
        findings=len(results.findings),
        cleared=results.counts_by_verdict()[Verdict.NOT_AFFECTED],
    )

    stored = await _fetch(connection, scan_id)
    # Notifications go out after the response, deliberately. A delivery talks
    # to somebody else's server over the network; doing it inside the request
    # would make this upload's latency, and its success, depend on whether
    # their endpoint is up. A CI job must not fail because a chat integration
    # is down.
    _queue_notifications(
        request,
        background,
        org_id=principal.org_id,
        project=project,
        scan=stored,
        results=results,
    )
    return stored


def _queue_notifications(
    request: Request,
    background: BackgroundTasks,
    *,
    org_id: str,
    project: Any,
    scan: ScanOut,
    results: ScanResults,
) -> None:
    """Schedule the webhook deliveries this upload should cause.

    Two events, because they answer different questions. ``scan.completed``
    says a scan happened and carries the counts, which is what a dashboard or
    a chat room wants. ``finding.new_reachable`` fires only when something can
    actually run, which is the one worth waking somebody for -- a subscriber
    who had to filter every scan to find that out would end up ignoring both.
    """
    engine = get_engine(request)
    secret_key = get_settings_from_app(request).secret_key
    common = {
        "project": project["slug"],
        "scan_id": scan.id,
        "created_at": scan.created_at.isoformat(),
        "git_ref": scan.git_ref,
        "git_sha": scan.git_sha,
        # Said in the payload, not inferred by the receiver: a clearance that
        # cannot be re-derived is an assertion, and a subscriber acting on
        # these counts deserves to know which kind they have.
        "reproducible": results.is_reproducible,
    }

    background.add_task(
        dispatch,
        engine,
        secret_key=secret_key,
        org_id=org_id,
        project_id=scan.project_id,
        event="scan.completed",
        payload={**common, "summary": scan.summary},
    )

    reachable = [
        finding
        for finding in results.findings
        if finding.reach is not None and finding.reach.status.is_reachable
    ]
    if reachable:
        background.add_task(
            dispatch,
            engine,
            secret_key=secret_key,
            org_id=org_id,
            project_id=scan.project_id,
            event="finding.new_reachable",
            payload={
                **common,
                "count": len(reachable),
                # A bounded sample rather than everything: a notification is a
                # pointer to the report, and a payload carrying ten thousand
                # findings is one nobody's endpoint will accept.
                "findings": [
                    {
                        "advisory_id": finding.advisory.id,
                        "severity": finding.advisory.severity.value,
                        "purl": finding.component.purl,
                        "status": finding.reach.status.value if finding.reach else None,
                    }
                    for finding in reachable[:20]
                ],
            },
        )


async def _store(
    connection: AsyncConnection,
    scan_id: str,
    project: Any,
    results: ScanResults,
    org_id: str,
    actor_id: str,
) -> None:
    """Write a whole scan.

    One transaction, held by the connection dependency. A half-stored scan
    would show findings whose evidence is missing, which reads as "nothing to
    see here" rather than as a broken upload.
    """
    await connection.execute(
        insert(scans).values(
            id=scan_id,
            org_id=org_id,
            project_id=project["id"],
            mode=results.mode.value,
            git_ref=results.project.git_ref,
            git_sha=results.project.git_sha,
            advisory_snapshot_id=results.advisory_snapshot_id,
            core_version=results.core_version,
            status="completed",
            summary=_summary(results),
            started_at=results.generated_at,
            finished_at=results.generated_at,
        )
    )

    if results.sbom is not None:
        await connection.execute(
            insert(sboms).values(
                id=new_ulid(),
                org_id=org_id,
                scan_id=scan_id,
                format=results.sbom.format,
                document_hash=results.sbom.sha256 or "",
                component_count=results.sbom.component_count,
                generated_by="vexpath",
            )
        )

    # One component row per distinct component a finding names. The full
    # inventory needs the SBOM document itself, which arrives with object
    # storage; what is stored here is what the findings refer to, so no
    # finding points at a component that is not there.
    sbom_row = (
        await connection.execute(select(sboms.c.id).where(sboms.c.scan_id == scan_id))
    ).one_or_none()
    component_ids: dict[str, str] = {}
    if sbom_row is not None:
        for finding in results.findings:
            if finding.component.purl in component_ids:
                continue
            component_id = new_ulid()
            component_ids[finding.component.purl] = component_id
            await connection.execute(
                insert(components).values(
                    id=component_id,
                    org_id=org_id,
                    sbom_id=sbom_row.id,
                    purl=finding.component.purl,
                    ecosystem=finding.component.ecosystem,
                    name=finding.component.name,
                    version=finding.component.version,
                    direct=finding.component.direct,
                    scope=_scope(finding.component.scope.value),
                    licenses=[],
                    hashes={},
                )
            )

    for finding in results.findings:
        # A finding whose component was not stored is skipped rather than
        # written with a dangling reference: a finding pointing at nothing is
        # worse in a report than a finding that is absent, because the absence
        # is at least visible as a count that does not add up.
        stored_component = component_ids.get(finding.component.purl)
        if stored_component is None:
            continue
        finding_id = new_ulid()
        await connection.execute(
            insert(findings).values(
                id=finding_id,
                org_id=org_id,
                scan_id=scan_id,
                component_id=stored_component,
                advisory_id=finding.advisory.id,
                severity=finding.advisory.severity.value,
                cvss_v3_score=finding.advisory.cvss_v3_score,
                epss_score=finding.advisory.epss_score,
                kev=finding.advisory.kev,
                fixed_in=finding.fixed_in,
                verdict=finding.verdict.value,
                justification=(
                    finding.justification.value if finding.justification is not None else None
                ),
                notes=list(finding.notes),
            )
        )

        if finding.reach is None:
            continue
        reach = finding.reach
        await connection.execute(
            insert(reachability_results).values(
                id=new_ulid(),
                org_id=org_id,
                finding_id=finding_id,
                status=reach.status.value,
                reason=reach.reason.value if reach.reason is not None else None,
                confidence=reach.confidence.value,
                matched_symbols=list(reach.matched_symbols),
                searched_symbols=list(reach.searched_symbols),
                shortest_path=[step.model_dump(mode="json") for step in reach.shortest_path],
                path_count=reach.path_count,
                via_dynamic_edges=reach.via_dynamic_edges,
                entry_points=(
                    reach.entry_points.model_dump(mode="json")
                    if reach.entry_points is not None
                    else None
                ),
                graph_stats=(
                    reach.graph_stats.model_dump(mode="json")
                    if reach.graph_stats is not None
                    else None
                ),
                explanation=reach.explanation,
            )
        )

    if results.policy is not None:
        await connection.execute(
            insert(policy_evaluations).values(
                id=new_ulid(),
                org_id=org_id,
                scan_id=scan_id,
                policy_id=None,
                cel=results.policy.name,
                passed=results.policy.passed,
                violations=[
                    violation.model_dump(mode="json") for violation in results.policy.violations
                ],
            )
        )

    await connection.execute(
        insert(audit_log).values(
            id=new_ulid(),
            org_id=org_id,
            actor_type="api_key",
            actor_id=actor_id,
            action="scan.uploaded",
            target_type="scan",
            target_id=scan_id,
            metadata={
                "project": project["slug"],
                "findings": len(results.findings),
                # Recorded because it is the difference between a verdict
                # someone can re-derive and one nobody can.
                "reproducible": results.is_reproducible,
            },
        )
    )


def _scope(value: str) -> str:
    """Map a result scope onto the column's vocabulary.

    The analysis calls a development dependency ``development``; the column
    says ``dev``. Translated in one place rather than letting a check
    constraint reject an upload for a reason nobody could act on.
    """
    return {"development": "dev"}.get(value, value)


def _summary(results: ScanResults) -> dict[str, Any]:
    """Counts for a listing, so a dashboard needs no per-scan query."""
    by_verdict = {verdict.value: count for verdict, count in results.counts_by_verdict().items()}
    return {
        "findings": len(results.findings),
        "by_verdict": by_verdict,
        "by_severity": {
            severity.value: count for severity, count in results.counts_by_severity().items()
        },
        "reachable": sum(
            1 for finding in results.findings if finding.reach and finding.reach.status.is_reachable
        ),
        "reproducible": results.is_reproducible,
        "policy_passed": results.policy.passed if results.policy is not None else None,
    }


@router.get("", response_model=list[ScanOut], summary="List scans")
async def list_scans(
    connection: TenantConnection,
    project: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ScanOut]:
    query = (
        select(scans, func.count(findings.c.id).label("finding_count"))
        .outerjoin(findings, findings.c.scan_id == scans.c.id)
        .group_by(scans.c.id)
        .order_by(scans.c.created_at.desc())
        .limit(limit)
    )
    if project is not None:
        query = query.where(
            scans.c.project_id.in_(select(projects.c.id).where(projects.c.slug == project))
        )
    rows = (await connection.execute(query)).mappings()
    return [_to_out(row) for row in rows]


@router.get("/{scan_id}", response_model=ScanOut, summary="Read one scan")
async def read_scan(scan_id: str, connection: TenantConnection) -> ScanOut:
    return await _fetch(connection, scan_id)


async def _fetch(connection: AsyncConnection, scan_id: str) -> ScanOut:
    row = (
        (
            await connection.execute(
                select(scans, func.count(findings.c.id).label("finding_count"))
                .outerjoin(findings, findings.c.scan_id == scans.c.id)
                .where(scans.c.id == scan_id)
                .group_by(scans.c.id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such scan")
    return _to_out(row)


def _to_out(row: Any) -> ScanOut:
    return ScanOut(
        id=row["id"],
        project_id=row["project_id"],
        mode=row["mode"],
        git_ref=row["git_ref"],
        git_sha=row["git_sha"],
        advisory_snapshot_id=row["advisory_snapshot_id"],
        core_version=row["core_version"],
        status=row["status"],
        summary=dict(row["summary"] or {}),
        created_at=row["created_at"],
        finding_count=int(row.get("finding_count") or 0),
    )


__all__ = ["MAX_FINDINGS", "router"]
