"""Public report pages and the badge.

What a project publishes when it wants to show its work. These are the pages
with no caller to authenticate, so they are also the ones where a mistake is
visible to everyone at once.

Three rules.

**Everything is in the first response.** No handler here returns a shell for
JavaScript to fill. A report page whose content arrives in a second request
cannot be read by a crawler, a feed reader, a text browser or anyone whose
network dropped the second request, and the whole purpose of publishing a
report is that other people can read it. The acceptance criterion asserts the
content is present in the initial HTML.

**The connection cannot see a private project.** These handlers take the
public connection, which carries no tenant context, so a private project's
rows are invisible to them however the query is written. A bug here produces
an empty page rather than a leak.

**A badge says what the scan said.** It is the most widely copied artefact a
project publishes, so it must not overstate. A project with reachable findings
gets a colour that says so, and one whose scan nobody can reproduce says that
too rather than claiming a clean bill of health.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_api.auth import PublicConnection
from vexpath_api.templating import render
from vexpath_core.enums import Verdict
from vexpath_db.tables import (
    advisories,
    components,
    findings,
    projects,
    reachability_results,
    scans,
    vulnerable_symbols,
)

router = APIRouter(tags=["public"])

#: Badge colours, in the shields.io palette so a published badge looks like
#: every other badge in a README rather than like something bespoke.
_COLOURS = {
    "reachable": "critical",
    "investigating": "important",
    "clear": "success",
    "unknown": "inactive",
}

#: How long a badge may be cached. Short, because the acceptance criterion is
#: that it reflects a new scan within five minutes, and a badge that lags
#: behind the report beside it is worse than no badge.
BADGE_MAX_AGE = 120


@router.get(
    "/p/{org_slug}/{project_slug:path}",
    response_class=HTMLResponse,
    include_in_schema=False,
    summary="Public report page",
)
async def report_page(
    org_slug: str, project_slug: str, request: Request, connection: PublicConnection
) -> HTMLResponse:
    """The published report for one project.

    Rendered whole, server-side. A 404 covers both "no such project" and "not
    published", because telling the difference would let anyone enumerate
    which private projects exist.
    """
    project = await _public_project(connection, org_slug, project_slug)
    scan = await _latest_scan(connection, project["id"])
    rows = await _findings(connection, scan["id"]) if scan is not None else []

    needs_attention = [row for row in rows if row["verdict"] != Verdict.NOT_AFFECTED.value]
    cleared = [row for row in rows if row["verdict"] == Verdict.NOT_AFFECTED.value]

    return render(
        request,
        "public_report.html",
        {
            "org_slug": org_slug,
            "project": project,
            "scan": scan,
            "needs_attention": needs_attention,
            "cleared": cleared,
            "total": len(rows),
            # Said on the page, not implied. An uploaded result is the client's
            # assertion until an attestation is verified against a
            # transparency log, and a reader deserves to know which they are
            # looking at.
            "self_reported": True,
            "reproducible": bool(scan and scan["advisory_snapshot_id"]),
        },
    )


@router.get(
    "/badge/{org_slug}/{project_slug:path}.svg",
    include_in_schema=False,
    summary="Status badge",
)
async def badge(
    org_slug: str,
    project_slug: str,
    connection: PublicConnection,
    style: Annotated[str, Query()] = "flat",
) -> Response:
    """An SVG badge for a README.

    Generated here rather than by redirecting to a badge service, because a
    redirect would tell that service every repository that embeds one, and
    which of them are looking at a vulnerable dependency.
    """
    del style  # accepted for compatibility; one rendering for now
    project = await _public_project(connection, org_slug, project_slug)
    scan = await _latest_scan(connection, project["id"])

    label, state = _badge_state(scan)
    svg = _render_badge("reachable", label, _COLOURS[state])
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": f"public, max-age={BADGE_MAX_AGE}",
            # A badge is embedded cross-origin by definition.
            "Access-Control-Allow-Origin": "*",
        },
    )


def _badge_state(scan: Any) -> tuple[str, str]:
    """What the badge says, and in what colour.

    Deliberately pessimistic where the answer is not known. A badge is the most
    widely copied thing a project publishes, so one that says "clear" when the
    analysis could not decide would be the single most misleading artefact this
    system could produce.
    """
    if scan is None:
        return "no scan", "unknown"

    summary = scan["summary"] or {}
    reachable = int(summary.get("reachable") or 0)
    by_verdict = summary.get("by_verdict") or {}
    investigating = int(by_verdict.get(Verdict.UNDER_INVESTIGATION.value) or 0)

    if reachable:
        return f"{reachable} reachable", "reachable"
    if investigating:
        return f"{investigating} unknown", "investigating"
    if not scan["advisory_snapshot_id"]:
        # The verdicts cannot be re-derived, so "none reachable" is an
        # assertion rather than a finding.
        return "none reachable (unverified)", "investigating"
    return "none reachable", "clear"


def _render_badge(label: str, message: str, colour: str) -> str:
    """A self-contained SVG, with no external reference of any kind.

    No font file, no stylesheet, no image. A badge that fetched anything would
    report every page view back to wherever it fetched from, and a badge in a
    README is viewed by everyone who looks at the repository.
    """
    palette = {
        "critical": "#e05d44",
        "important": "#dfb317",
        "success": "#4c1",
        "inactive": "#9f9f9f",
    }
    fill = palette.get(colour, palette["inactive"])
    label_width = 8 + 7 * len(label)
    message_width = 10 + 7 * len(message)
    total = label_width + message_width

    # Escaped by hand because this is not a template: the values come from a
    # project slug and a scan summary, and an unescaped angle bracket here
    # would be script injection into every page that embeds the badge.
    safe_label = _escape(label)
    safe_message = _escape(message)

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{safe_label}: {safe_message}">'
        f"<title>{safe_label}: {safe_message}</title>"
        f'<g shape-rendering="crispEdges">'
        f'<rect width="{label_width}" height="20" fill="#555"/>'
        f'<rect x="{label_width}" width="{message_width}" height="20" fill="{fill}"/>'
        f"</g>"
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{label_width / 2}" y="14">{safe_label}</text>'
        f'<text x="{label_width + message_width / 2}" y="14">{safe_message}</text>'
        f"</g></svg>"
    )


def _escape(value: str) -> str:
    """Escape for XML text and attribute content.

    Written out rather than imported so the set is visible: these five are the
    ones that matter inside both a text node and a double-quoted attribute.
    """
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


@router.get(
    "/package/{ecosystem}/{name:path}",
    response_class=HTMLResponse,
    include_in_schema=False,
    summary="Public package page",
)
async def package_page(
    ecosystem: str, name: str, request: Request, connection: PublicConnection
) -> HTMLResponse:
    """What is known about one package, from the advisory corpus.

    No tenant data: this page is built entirely from the global corpus, which
    is world-readable by design. That is what lets it exist without an
    organisation in scope, and why it is useful to someone who has never
    uploaded anything.
    """
    rows = (
        await connection.execute(
            select(
                advisories.c.id,
                advisories.c.summary,
                advisories.c.severity,
                advisories.c.epss_score,
                advisories.c.kev,
                advisories.c.symbols_status,
                advisories.c.withdrawn_at,
                func.count(vulnerable_symbols.c.id).label("symbol_count"),
            )
            .select_from(advisories)
            .join(
                vulnerable_symbols,
                (vulnerable_symbols.c.advisory_id == advisories.c.id)
                & (vulnerable_symbols.c.package_name == name)
                & (vulnerable_symbols.c.ecosystem == ecosystem),
                isouter=True,
            )
            .where(
                advisories.c.id.in_(
                    select(vulnerable_symbols.c.advisory_id).where(
                        (vulnerable_symbols.c.package_name == name)
                        & (vulnerable_symbols.c.ecosystem == ecosystem)
                    )
                )
            )
            .group_by(advisories.c.id)
            .order_by(advisories.c.id.desc())
            .limit(200)
        )
    ).mappings()
    advisory_rows = [dict(row) for row in rows]

    symbols = (
        await connection.execute(
            select(
                vulnerable_symbols.c.advisory_id,
                vulnerable_symbols.c.symbol,
                vulnerable_symbols.c.kind,
                vulnerable_symbols.c.source,
                vulnerable_symbols.c.confidence,
                vulnerable_symbols.c.file_path,
            )
            .where(
                (vulnerable_symbols.c.package_name == name)
                & (vulnerable_symbols.c.ecosystem == ecosystem)
            )
            .order_by(vulnerable_symbols.c.advisory_id.desc(), vulnerable_symbols.c.symbol)
            .limit(2000)
        )
    ).mappings()

    by_advisory: dict[str, list[dict[str, Any]]] = {}
    for symbol in symbols:
        by_advisory.setdefault(symbol["advisory_id"], []).append(dict(symbol))

    return render(
        request,
        "public_package.html",
        {
            "ecosystem": ecosystem,
            "name": name,
            "advisories": advisory_rows,
            "symbols_by_advisory": by_advisory,
            "symbol_total": sum(len(items) for items in by_advisory.values()),
        },
    )


async def _public_project(connection: AsyncConnection, org_slug: str, slug: str) -> Any:
    """The project, if it is published.

    The connection cannot see an unpublished one, so this is a lookup rather
    than a check: there is no code path that could forget the visibility
    condition, because the condition is in the database's policy.
    """
    row = (
        (await connection.execute(select(projects).where(projects.c.slug == slug)))
        .mappings()
        .one_or_none()
    )
    if row is None:
        # 404 for "no such project" and for "not published" alike. Telling
        # them apart would let anyone enumerate private projects by name.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such report")
    del org_slug  # part of the URL for readability; the slug is the key
    return row


async def _latest_scan(connection: AsyncConnection, project_id: str) -> Any:
    return (
        (
            await connection.execute(
                select(scans)
                .where(scans.c.project_id == project_id)
                .order_by(scans.c.created_at.desc())
                .limit(1)
            )
        )
        .mappings()
        .one_or_none()
    )


async def _findings(connection: AsyncConnection, scan_id: str) -> list[Any]:
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
                findings.c.fixed_in,
                components.c.name.label("component_name"),
                components.c.version.label("component_version"),
                components.c.purl,
                components.c.direct,
                reachability_results.c.status.label("reach_status"),
                reachability_results.c.confidence.label("reach_confidence"),
                reachability_results.c.explanation,
                reachability_results.c.shortest_path,
                reachability_results.c.searched_symbols,
                reachability_results.c.entry_points,
            )
            .join(components, components.c.id == findings.c.component_id)
            .outerjoin(reachability_results, reachability_results.c.finding_id == findings.c.id)
            .where(findings.c.scan_id == scan_id)
            .limit(1000)
        )
    ).mappings()

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return sorted(
        (dict(row) for row in rows),
        key=lambda row: (order.get(row["severity"], 9), not row["kev"], row["advisory_id"]),
    )


__all__ = ["BADGE_MAX_AGE", "router"]
