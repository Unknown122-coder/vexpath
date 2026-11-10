"""Findings and their evidence.

The read path the whole product exists to serve. A finding on its own is what
every scanner already gives you; what makes this one worth reading is the
evidence beside it, so the evidence is part of the finding here rather than
something to fetch separately.

Two decisions shape the shape of the response.

**Cleared findings are returned, not hidden.** The point of the analysis is a
short list, and the default ordering puts what needs attention first. But a
clearance a consumer cannot see is a clearance they cannot check, and "trust
me, I removed 28 of your 38 findings" is exactly the claim that needs
checking.

**The reachability result travels inline.** A client that has to make a second
request for the call path will render a list without it, and a list of
verdicts with no evidence is indistinguishable from any other scanner's
output.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_api.auth import TenantConnection
from vexpath_core.enums import Verdict
from vexpath_db.tables import components, findings, reachability_results, scans

router = APIRouter(prefix="/v1", tags=["findings"])

#: Worst first. Reachable before possibly reachable before unknown before
#: cleared, so the first screen is the part someone has to act on.
_VERDICT_ORDER = {
    Verdict.AFFECTED.value: 0,
    Verdict.UNDER_INVESTIGATION.value: 1,
    Verdict.FIXED.value: 2,
    Verdict.NOT_AFFECTED.value: 3,
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


class PathStepOut(BaseModel):
    """One hop of a call path."""

    symbol: str
    file: str | None = None
    line: int | None = None
    edge_kind: str | None = None


class ReachabilityOut(BaseModel):
    """Why a finding got the verdict it did."""

    status: str
    reason: str | None
    confidence: str
    matched_symbols: list[str]
    searched_symbols: list[str]
    shortest_path: list[PathStepOut]
    path_count: int
    via_dynamic_edges: bool
    entry_points: dict[str, Any] | None
    graph_stats: dict[str, Any] | None
    explanation: str


class FindingOut(BaseModel):
    """A finding, with the evidence for its verdict."""

    id: str
    scan_id: str
    advisory_id: str
    severity: str
    cvss_v3_score: float | None
    epss_score: float | None
    kev: bool
    fixed_in: str | None
    verdict: str
    justification: str | None
    notes: list[str]
    component: dict[str, Any]
    reach: ReachabilityOut | None


@router.get(
    "/scans/{scan_id}/findings",
    response_model=list[FindingOut],
    summary="Findings of one scan, with evidence",
)
async def list_findings(
    scan_id: str,
    connection: TenantConnection,
    verdict: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    reachable_only: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[FindingOut]:
    """Every finding of a scan, worst first.

    Raises:
        HTTPException: 404 if the scan does not exist for this organisation.
            The same answer whether it belongs to someone else or to nobody,
            because distinguishing them would make this a way of asking what
            other organisations have scanned.
    """
    exists = (
        await connection.execute(select(scans.c.id).where(scans.c.id == scan_id))
    ).one_or_none()
    if exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such scan")

    rows = await _rows(connection, scan_id=scan_id, limit=limit)
    results = [_to_out(row) for row in rows]

    if verdict is not None:
        results = [finding for finding in results if finding.verdict == verdict]
    if severity is not None:
        wanted = severity.upper()
        results = [finding for finding in results if finding.severity == wanted]
    if reachable_only:
        results = [
            finding
            for finding in results
            if finding.reach is not None
            and finding.reach.status in {"reachable_confirmed", "reachable_possible"}
        ]
    return results


@router.get(
    "/findings/{finding_id}",
    response_model=FindingOut,
    summary="One finding, with evidence",
)
async def read_finding(finding_id: str, connection: TenantConnection) -> FindingOut:
    rows = await _rows(connection, finding_id=finding_id, limit=1)
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such finding")
    return _to_out(rows[0])


async def _rows(
    connection: AsyncConnection,
    *,
    scan_id: str | None = None,
    finding_id: str | None = None,
    limit: int = 200,
) -> list[Any]:
    """Read findings with their component and evidence in one query.

    One query rather than three, because a list of two hundred findings each
    fetching its own evidence is two hundred round trips, and the evidence is
    what makes the list worth showing.
    """
    query = (
        select(
            findings,
            components.c.purl,
            components.c.ecosystem,
            components.c.name.label("component_name"),
            components.c.version.label("component_version"),
            components.c.direct,
            components.c.scope,
            reachability_results.c.status.label("reach_status"),
            reachability_results.c.reason.label("reach_reason"),
            reachability_results.c.confidence.label("reach_confidence"),
            reachability_results.c.matched_symbols,
            reachability_results.c.searched_symbols,
            reachability_results.c.shortest_path,
            reachability_results.c.path_count,
            reachability_results.c.via_dynamic_edges,
            reachability_results.c.entry_points,
            reachability_results.c.graph_stats,
            reachability_results.c.explanation,
        )
        .join(components, components.c.id == findings.c.component_id)
        .outerjoin(reachability_results, reachability_results.c.finding_id == findings.c.id)
        .limit(limit)
    )
    if scan_id is not None:
        query = query.where(findings.c.scan_id == scan_id)
    if finding_id is not None:
        query = query.where(findings.c.id == finding_id)

    rows = list((await connection.execute(query)).mappings())
    # Ordered here rather than in SQL: the order is a product decision about
    # what someone should look at first, and expressing it as a CASE ladder
    # would bury it in a query nobody reads.
    rows.sort(
        key=lambda row: (
            _VERDICT_ORDER.get(row["verdict"], 9),
            _SEVERITY_ORDER.get(row["severity"], 9),
            not row["kev"],
            -(row["epss_score"] or 0.0),
            row["advisory_id"],
        )
    )
    return rows


def _to_out(row: Any) -> FindingOut:
    return FindingOut(
        id=row["id"],
        scan_id=row["scan_id"],
        advisory_id=row["advisory_id"],
        severity=row["severity"],
        cvss_v3_score=row["cvss_v3_score"],
        epss_score=row["epss_score"],
        kev=row["kev"],
        fixed_in=row["fixed_in"],
        verdict=row["verdict"],
        justification=row["justification"],
        notes=list(row["notes"] or []),
        component={
            "purl": row["purl"],
            "ecosystem": row["ecosystem"],
            "name": row["component_name"],
            "version": row["component_version"],
            "direct": row["direct"],
            "scope": row["scope"],
        },
        reach=_reach(row),
    )


def _reach(row: Any) -> ReachabilityOut | None:
    """The evidence, when there is any.

    None means reachability did not run for this finding, which is a different
    statement from "it was not reachable" and must stay distinguishable.
    """
    if row["reach_status"] is None:
        return None
    return ReachabilityOut(
        status=row["reach_status"],
        reason=row["reach_reason"],
        confidence=row["reach_confidence"],
        matched_symbols=list(row["matched_symbols"] or []),
        searched_symbols=list(row["searched_symbols"] or []),
        shortest_path=[
            PathStepOut(
                symbol=step.get("symbol", ""),
                file=step.get("file"),
                line=step.get("line"),
                edge_kind=step.get("edge_kind"),
            )
            for step in (row["shortest_path"] or [])
        ],
        path_count=row["path_count"],
        via_dynamic_edges=row["via_dynamic_edges"],
        entry_points=row["entry_points"],
        graph_stats=row["graph_stats"],
        explanation=row["explanation"],
    )


__all__ = ["router"]
