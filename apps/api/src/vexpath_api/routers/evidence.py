"""Scan and finding pages: the evidence behind a verdict.

This is the screen the product exists for. Every other scanner can show a list
of advisory identifiers; what nobody shows is *why* a finding was kept or
dropped, and that is the only part a person can actually check.

So these pages are built around a rule: **a verdict is never shown without the
evidence for it.** A reachable finding shows the path, hop by hop, with the
file and line of each call and which hop was resolved conservatively. A cleared
finding shows the symbols that were searched for and the entry points the
search started from, because "not reachable" means nothing unless you know what
was looked for and from where. A finding nobody could analyse says so in those
words rather than rendering a blank panel that reads as "fine".

The call path is rendered server-side as an ordered list. A path that arrived
by script would be invisible to a crawler, to a text browser, and to anybody
reading a saved page, and the whole value of the evidence is that it travels.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_api.session import RequiredSession, SessionConnection
from vexpath_api.suppress import applicable, remaining_days
from vexpath_api.templating import render
from vexpath_core.enums import Verdict
from vexpath_db.tables import (
    components,
    findings,
    projects,
    reachability_results,
    sboms,
    scans,
    suppressions,
)

router = APIRouter(prefix="/app", tags=["dashboard"], include_in_schema=False)

#: Needs-attention first, then by how much trouble it is. The ordering is the
#: product: a list sorted by advisory identifier would make the analysis
#: pointless, because the reader would still have to read all of it.
VERDICT_ORDER = {
    Verdict.AFFECTED.value: 0,
    Verdict.UNDER_INVESTIGATION.value: 1,
    Verdict.FIXED.value: 2,
    Verdict.NOT_AFFECTED.value: 3,
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

#: How many findings one page renders. A scan of a large monorepo can carry
#: thousands, and a page that tried to show them all would be unreadable
#: before it was slow.
PAGE_SIZE = 500


@router.get("/projects/{slug:path}", response_class=HTMLResponse, summary="One project")
async def project_page(
    slug: str, request: Request, session: RequiredSession, connection: SessionConnection
) -> HTMLResponse:
    """A project and its scans, most recent first.

    404 for a project of another organisation, exactly as for one that does not
    exist: the connection cannot see it, so this is a lookup rather than a
    check.
    """
    project = (
        (await connection.execute(select(projects).where(projects.c.slug == slug)))
        .mappings()
        .one_or_none()
    )
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such project")

    rows = (
        await connection.execute(
            select(
                scans.c.id,
                scans.c.created_at,
                scans.c.mode,
                scans.c.status,
                scans.c.git_ref,
                scans.c.git_sha,
                scans.c.core_version,
                scans.c.advisory_snapshot_id,
                scans.c.summary,
                func.count(findings.c.id).label("finding_count"),
            )
            .outerjoin(findings, findings.c.scan_id == scans.c.id)
            .where(scans.c.project_id == project["id"])
            .group_by(scans.c.id)
            .order_by(scans.c.created_at.desc())
            .limit(100)
        )
    ).mappings()

    return render(
        request,
        "app_project.html",
        {"session": session, "project": dict(project), "scans": [dict(row) for row in rows]},
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse, summary="One scan")
async def scan_page(
    scan_id: str, request: Request, session: RequiredSession, connection: SessionConnection
) -> HTMLResponse:
    """Everything one scan found, ordered so the top of the page is the work.

    Cleared findings are listed too, below. Hiding them would make the central
    claim -- "28 of these 38 cannot run" -- unverifiable, and that claim is
    exactly the one a reader should want to check.
    """
    scan = (
        (await connection.execute(select(scans).where(scans.c.id == scan_id)))
        .mappings()
        .one_or_none()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such scan")

    project = (
        (await connection.execute(select(projects).where(projects.c.id == scan["project_id"])))
        .mappings()
        .one()
    )
    sbom = (
        (await connection.execute(select(sboms).where(sboms.c.scan_id == scan_id)))
        .mappings()
        .one_or_none()
    )
    rows = await _findings(connection, scan_id)

    return render(
        request,
        "app_scan.html",
        {
            "session": session,
            "scan": dict(scan),
            "project": dict(project),
            "sbom": dict(sbom) if sbom is not None else None,
            "needs_attention": [
                row for row in rows if row["verdict"] != Verdict.NOT_AFFECTED.value
            ],
            "cleared": [row for row in rows if row["verdict"] == Verdict.NOT_AFFECTED.value],
            "total": len(rows),
            "truncated": len(rows) >= PAGE_SIZE,
        },
    )


async def _findings(connection: AsyncConnection, scan_id: str) -> list[dict[str, Any]]:
    """One joined query, sorted in Python.

    Joined rather than fetched per finding: two hundred findings each asking
    for their own evidence is two hundred round trips, and the page would be
    slow for exactly the scans that matter most.

    Sorted here rather than in SQL because the order is a product decision
    expressed over two enumerations, and writing it as a CASE expression would
    bury it.
    """
    rows = (
        await connection.execute(
            select(
                findings.c.id,
                findings.c.advisory_id,
                findings.c.severity,
                findings.c.verdict,
                findings.c.justification,
                findings.c.kev,
                findings.c.epss_score,
                findings.c.cvss_v3_score,
                findings.c.fixed_in,
                components.c.name.label("component_name"),
                components.c.version.label("component_version"),
                components.c.purl,
                components.c.direct,
                components.c.scope,
                reachability_results.c.status.label("reach_status"),
                reachability_results.c.confidence.label("reach_confidence"),
                reachability_results.c.reason.label("reach_reason"),
                reachability_results.c.explanation,
                reachability_results.c.matched_symbols,
                reachability_results.c.searched_symbols,
                reachability_results.c.path_count,
            )
            .join(components, components.c.id == findings.c.component_id)
            .outerjoin(reachability_results, reachability_results.c.finding_id == findings.c.id)
            .where(findings.c.scan_id == scan_id)
            .limit(PAGE_SIZE)
        )
    ).mappings()

    return sorted(
        (dict(row) for row in rows),
        key=lambda row: (
            VERDICT_ORDER.get(row["verdict"], 9),
            SEVERITY_ORDER.get(row["severity"], 9),
            not row["kev"],
            -(row["epss_score"] or 0.0),
            row["advisory_id"],
        ),
    )


#: What a refused suppression says. A closed vocabulary rather than text
#: echoed from the query string: a sentence taken from a URL and rendered on a
#: page is how a phishing message gets hosted on somebody else's domain, and
#: autoescaping stops the markup rather than the sentence.
PROBLEMS = {
    "reason": (
        "That suppression needs a reason. One nobody explained cannot be "
        "reviewed, and an unreviewable suppression is how a vulnerability "
        "stays hidden."
    ),
    "duration": (
        "A suppression has to run for at least a day and at most 730. Beyond "
        "that the expiry is a formality, which is the thing an expiry exists "
        "to prevent."
    ),
    "invalid": "That suppression could not be recorded.",
}


@router.get("/findings/{finding_id}", response_class=HTMLResponse, summary="One finding")
async def finding_page(
    finding_id: str,
    request: Request,
    session: RequiredSession,
    connection: SessionConnection,
    problem: Annotated[str | None, Query()] = None,
) -> HTMLResponse:
    """One finding, with the whole chain of reasoning behind its verdict.

    The page a developer opens when they disagree with the tool, which is the
    use it has to survive. So it shows what was searched for, where the search
    began, how good the graph was, and -- when there is one -- the path itself,
    hop by hop, naming any hop that was resolved conservatively rather than
    proven.
    """
    row = (
        (
            await connection.execute(
                select(
                    findings,
                    components.c.name.label("component_name"),
                    components.c.version.label("component_version"),
                    components.c.purl,
                    components.c.direct,
                    components.c.scope,
                    scans.c.project_id,
                    scans.c.created_at.label("scan_created_at"),
                    scans.c.advisory_snapshot_id,
                    scans.c.core_version,
                )
                .join(components, components.c.id == findings.c.component_id)
                .join(scans, scans.c.id == findings.c.scan_id)
                .where(findings.c.id == finding_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such finding")

    reach = (
        (
            await connection.execute(
                select(reachability_results).where(reachability_results.c.finding_id == finding_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    project = (
        (await connection.execute(select(projects).where(projects.c.id == row["project_id"])))
        .mappings()
        .one()
    )

    # The suppression, if there is one. Fetched and shown rather than used to
    # hide the finding: a suppression is a decision about what to work on, not
    # a change to what the analysis found, and the evidence underneath it
    # stays exactly as it was.
    stored = [
        dict(entry)
        for entry in (
            await connection.execute(
                select(suppressions).where(suppressions.c.project_id == row["project_id"])
            )
        ).mappings()
    ]
    suppression = applicable(stored, advisory_id=row["advisory_id"], purl=row["purl"])

    return render(
        request,
        "app_finding.html",
        {
            "session": session,
            "finding": dict(row),
            "project": dict(project),
            "reach": dict(reach) if reach is not None else None,
            "path": _path_steps(reach),
            "problem": PROBLEMS.get(problem or ""),
            "suppression": suppression,
            "suppression_days": remaining_days(suppression) if suppression else 0,
            # Said rather than implied. A clearance with no analysis behind it
            # is not a clearance, and the page must not look the same as one
            # that was actually proved.
            "analysed": reach is not None,
        },
    )


def _path_steps(reach: Any) -> list[dict[str, Any]]:
    """The call path as a list of rendered steps.

    Normalised here rather than in the template, because the stored value came
    from an uploaded document: it is whatever the client sent, and a template
    that indexed into it blindly would raise on a malformed path. A step that
    is not an object is dropped rather than rendered as its repr.
    """
    if reach is None:
        return []
    raw = reach["shortest_path"] or []
    if not isinstance(raw, list):
        return []

    steps: list[dict[str, Any]] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        symbol = item.get("symbol")
        if not isinstance(symbol, str):
            continue
        edge = item.get("edge_kind")
        steps.append(
            {
                "index": index,
                "symbol": symbol,
                "file": item.get("file") if isinstance(item.get("file"), str) else None,
                "line": item.get("line") if isinstance(item.get("line"), int) else None,
                "edge_kind": edge if isinstance(edge, str) else "static",
                # Named on the page, because one such hop is the difference
                # between a proven path and a conservative guess, and a reader
                # deciding whether to act deserves to know which they have.
                "conservative": edge in {"dynamic", "opaque"},
            }
        )
    return steps


__all__ = ["PAGE_SIZE", "PROBLEMS", "SEVERITY_ORDER", "VERDICT_ORDER", "router"]
