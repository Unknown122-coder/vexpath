"""The policy editor.

A gate is the one piece of configuration whose mistakes are invisible in both
directions: too loose and nobody notices, too tight and the build everybody
needs is red. So this screen does the thing that makes a gate writable at all
— it runs the candidate expression against the project's **last real scan**
and says what it would have done.

What this screen is not: a second gate. `vexpath scan --policy` evaluates
locally, in CI, with no knowledge of the platform, and that is deliberate (a
build must not depend on a dashboard being reachable). So the expression saved
here is the one to put in `.vexpath.yml` or pass to `--policy`, and the page
says so rather than implying a gate it does not enforce. Inventing a
server-side gate that silently disagreed with the one in CI would be worse
than having none.

Two refusals worth stating. **An expression that will not compile is never
stored** — a gate nobody can evaluate must not be recorded as a gate. And a
stored expression is a new row rather than an edit, so "who loosened this and
when" has an answer.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncConnection

from vexpath_core.policy import (
    DEFAULT_PRESET,
    PRESETS,
    PolicyError,
    compile_policy,
    explain,
)
from vexpath_db.tables import components, findings, policies, reachability_results, scans

#: The longest expression accepted. CEL has no loops, so an expression cannot
#: run forever; what it can do is be absurdly long. A cap keeps the editor a
#: text field rather than a submission channel.
MAX_EXPRESSION = 4000


async def current_policy(connection: AsyncConnection, project_id: str) -> dict[str, Any] | None:
    """The newest stored policy for a project, or None.

    Newest by version rather than by time, because a row is only ever added
    and the version is what the page shows.
    """
    row = (
        (
            await connection.execute(
                select(policies)
                .where(policies.c.project_id == project_id)
                .order_by(policies.c.version.desc())
                .limit(1)
            )
        )
        .mappings()
        .one_or_none()
    )
    return dict(row) if row is not None else None


async def next_version(connection: AsyncConnection, project_id: str) -> int:
    highest = (
        await connection.execute(
            select(func.max(policies.c.version)).where(policies.c.project_id == project_id)
        )
    ).scalar_one_or_none()
    return int(highest or 0) + 1


def preset_descriptions() -> list[dict[str, str]]:
    """Each preset with its expression and what it does, for the page.

    Read from the core module rather than restated here: a description that
    drifted from the expression would be worse than no description, because
    somebody would choose on the strength of it.
    """
    return [
        {"name": name, "expression": PRESETS[name], "description": explain(name)}
        for name in PRESETS
    ]


async def context_for_scan(connection: AsyncConnection, scan: Any) -> dict[str, Any]:
    """The policy variables for one stored scan, assembled from its rows.

    The platform keeps findings as rows rather than the uploaded document, so
    this rebuilds what ``vexpath_core.policy.raw_context`` builds from the
    document. The field names come from the same place and a test asserts the
    two agree: a field present in one and absent from the other would change
    what an expression means between CI and this page, and an expression that
    errors is a build failing for the wrong reason.
    """
    rows = (
        await connection.execute(
            select(
                findings.c.id,
                findings.c.advisory_id,
                findings.c.severity,
                findings.c.cvss_v3_score,
                findings.c.epss_score,
                findings.c.kev,
                findings.c.verdict,
                findings.c.justification,
                findings.c.fixed_in,
                findings.c.suppressed_by,
                findings.c.created_at,
                components.c.name.label("component_name"),
                components.c.version.label("component_version"),
                components.c.purl,
                components.c.ecosystem,
                components.c.direct,
                components.c.scope,
                reachability_results.c.status.label("reach_status"),
                reachability_results.c.reason.label("reach_reason"),
                reachability_results.c.confidence.label("reach_confidence"),
                reachability_results.c.shortest_path,
                reachability_results.c.via_dynamic_edges,
            )
            .join(components, components.c.id == findings.c.component_id)
            .outerjoin(reachability_results, reachability_results.c.finding_id == findings.c.id)
            .where(findings.c.scan_id == scan["id"])
            .limit(50_000)
        )
    ).mappings()

    entries = [_entry(row) for row in rows]
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1

    return {
        "findings": entries,
        "scan": {
            "mode": scan["mode"],
            "git_ref": scan["git_ref"] or "",
            "git_sha": scan["git_sha"] or "",
            # The same meaning as in the document: a pinned advisory corpus is
            # what makes a verdict re-derivable.
            "reproducible": bool(scan["advisory_snapshot_id"]),
            "snapshot": scan["advisory_snapshot_id"] or "",
        },
        "project": {"slug": scan["project_slug"]},
        "counts": counts,
    }


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
_REACHABLE = {"reachable_confirmed", "reachable_possible"}


def _entry(row: Any) -> dict[str, Any]:
    """One finding, in the shape a policy sees.

    Nothing is ``null``: a policy comparing against a missing field errors at
    evaluation time, which turns a reasonable expression into a broken build.
    Absent values get the empty string, zero or false, exactly as the
    document-based builder does.
    """
    analysed = row["reach_status"] is not None
    confidence = row["reach_confidence"] or ""
    path = row["shortest_path"] or []
    return {
        "id": row["id"],
        "advisory": row["advisory_id"],
        # Aliases are not stored per finding, so this is empty rather than
        # absent: an expression using it must not error, it must just not
        # match.
        "aliases": [],
        "component": row["component_name"],
        "purl": row["purl"],
        "ecosystem": row["ecosystem"],
        "version": row["component_version"],
        "severity": row["severity"],
        "severity_rank": _SEVERITY_RANK.get(row["severity"], 0),
        "cvss": row["cvss_v3_score"] or 0.0,
        "cvss_v4": 0.0,
        "epss": row["epss_score"] or 0.0,
        "kev": bool(row["kev"]),
        "verdict": row["verdict"],
        "justification": row["justification"] or "",
        "fixed_in": row["fixed_in"] or "",
        "has_fix": bool(row["fixed_in"]),
        "age_days": 0,
        "scope": row["scope"],
        "direct": bool(row["direct"]),
        "suppressed": row["suppressed_by"] is not None,
        "reach": {
            "analysed": analysed,
            "status": row["reach_status"] or "",
            "reason": row["reach_reason"] or "",
            "confidence": confidence,
            "confidence_rank": _CONFIDENCE_RANK.get(confidence, 0),
            "reachable": row["reach_status"] in _REACHABLE,
            "path_length": len(path) if isinstance(path, list) else 0,
            "via_dynamic_edges": bool(row["via_dynamic_edges"]),
        },
    }


async def latest_scan(connection: AsyncConnection, project_id: str, slug: str) -> Any:
    """The scan a candidate policy is tried against, or None.

    The most recent one, because that is the build somebody is reasoning
    about. Trying a gate against a six-month-old scan would answer a question
    nobody asked.
    """
    row = (
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
    if row is None:
        return None
    return {**dict(row), "project_slug": slug}


def check(expression: str) -> tuple[str | None, str | None]:
    """Compile a candidate expression.

    Returns the resolved expression and an error message, exactly one of which
    is None. A preset name resolves to its expression here, so a stored policy
    is always the expression itself: a name whose meaning changed in a later
    release would otherwise silently change what a project gates on.
    """
    candidate = expression.strip()
    if not candidate:
        return None, (
            "A policy needs an expression. To gate on nothing, use the "
            "report-only preset, so the choice is visible rather than implied."
        )
    if len(candidate) > MAX_EXPRESSION:
        return None, f"That expression is longer than {MAX_EXPRESSION} characters."
    try:
        compiled = compile_policy(candidate)
    except PolicyError as exc:
        # Never stored. A gate nobody can evaluate must not be recorded as a
        # gate, because the next person to read the configuration would
        # believe it was one.
        return None, str(exc)
    return compiled.expression, None


def dry_run(expression: str, context: dict[str, Any]) -> dict[str, Any]:
    """What this expression would have done to that scan.

    Returns the outcome and the findings it blamed. An expression that cannot
    be evaluated against real data is reported as an error rather than as a
    pass, for the same reason the command line exits 3 on a broken policy: a
    gate that failed to run must never look like a gate that was satisfied.
    """
    try:
        compiled = compile_policy(expression)
        result = compiled.evaluate_context(context)
    except PolicyError as exc:
        return {"ok": False, "error": str(exc)}
    return {
        "ok": True,
        "passed": result.passed,
        "violations": [
            {
                "message": violation.message,
                "finding_id": violation.finding_id,
                "advisory_id": violation.advisory_id,
            }
            for violation in result.violations
        ],
    }


__all__ = [
    "DEFAULT_PRESET",
    "MAX_EXPRESSION",
    "check",
    "context_for_scan",
    "current_policy",
    "dry_run",
    "latest_scan",
    "next_version",
    "preset_descriptions",
]
