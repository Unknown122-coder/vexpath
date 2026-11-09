"""Render results for people and for machines.

Every surface this project has, the terminal, the pull-request comment, the web
page and the SARIF upload, is rendered from the same `ScanResults` by this
module. That is deliberate: when the rendering lives in one place, the terminal
output and the web page cannot quietly disagree about what a finding says.

Rendering is plain text, with no terminal-styling dependency, so the analysis
core stays importable anywhere. Colour is the command-line tool's business.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from vexpath_core.enums import ReachStatus, Severity, Verdict
from vexpath_core.models.finding import Finding
from vexpath_core.models.results import ScanResults

#: Column widths for the terminal table. Severity and verdict are fixed-width
#: vocabularies, so the table does not need to measure them.
_SEVERITY_WIDTH = 8
_VERDICT_WIDTH = 19

#: SARIF requires a level from a fixed set, and maps severity onto it. Only
#: findings that need attention become warnings or errors; a cleared finding is
#: a note so it stays visible without failing anything.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.UNKNOWN: "warning",
    Severity.NONE: "note",
}


def render_text(results: ScanResults, *, show_cleared: bool = False) -> str:
    """Render results as a plain-text report for a terminal.

    Findings that were cleared are hidden by default and counted in the
    summary instead. The whole point of the product is to show a short list, so
    the default output is the short list.
    """
    lines: list[str] = []
    shown = [
        finding
        for finding in results.findings
        if show_cleared or finding.verdict is not Verdict.NOT_AFFECTED
    ]

    header = _header(results)
    lines.extend(header)

    if not results.findings:
        lines.append("No advisories match any component in this inventory.")
        return "\n".join(lines) + "\n"

    if not shown:
        lines.append(
            f"All {len(results.findings)} findings were cleared as unreachable. "
            "Re-run with --show-cleared to list them."
        )
        lines.append("")
        lines.append(results.summary_line())
        return "\n".join(lines) + "\n"

    lines.append("")
    lines.append(
        f"{'SEVERITY':<{_SEVERITY_WIDTH}}  {'VERDICT':<{_VERDICT_WIDTH}}  "
        f"{'ADVISORY':<20}  COMPONENT"
    )
    lines.append("-" * 96)
    for finding in shown:
        lines.append(_finding_row(finding))

    evidence = [finding for finding in shown if finding.reach is not None]
    if evidence:
        lines.append("")
        lines.append("Evidence")
        for finding in evidence:
            lines.extend(_evidence_block(finding))

    notes = [(finding.advisory.id, note) for finding in shown for note in finding.notes]
    if notes:
        lines.append("")
        lines.append("Caveats")
        for advisory_id, note in notes:
            lines.append(f"  {advisory_id}: {note}")

    lines.append("")
    lines.extend(_footer(results))
    return "\n".join(lines) + "\n"


def _header(results: ScanResults) -> list[str]:
    lines: list[str] = []
    target = results.project.slug or "this project"
    if results.sbom is not None:
        count = results.sbom.component_count
        lines.append(
            f"Scanned {target}: {count} component{'' if count == 1 else 's'} "
            f"from {results.sbom.format.value}."
        )
    else:
        lines.append(f"Scanned {target}.")

    if results.entry_points is not None:
        lines.append(
            f"Entry points: {results.entry_points.count} "
            f"({results.entry_points.source.value.replace('_', ' ')})."
        )

    if not results.is_reproducible:
        # A reader has to be able to tell a reproducible scan from a live one,
        # because only the first can be re-derived and compared later.
        lines.append(
            "Advisories were read live, so this scan is not reproducible. "
            "Use a local snapshot to make it so."
        )
    if results.unsupported_reachability_ecosystems:
        listed = ", ".join(results.unsupported_reachability_ecosystems)
        lines.append(
            f"Reachability analysis does not cover {listed}. Findings for those "
            f"components are reported as under investigation, not cleared."
        )
    return lines


def _finding_row(finding: Finding) -> str:
    verdict = _verdict_label(finding)
    component = f"{finding.component.name} {finding.component.version}"
    if not finding.component.direct:
        component += " (transitive)"
    if finding.fixed_in:
        component += f" -> {finding.fixed_in}"
    return (
        f"{finding.advisory.severity.value:<{_SEVERITY_WIDTH}}  "
        f"{verdict:<{_VERDICT_WIDTH}}  "
        f"{finding.advisory.id:<20}  {component}"
    )


def _verdict_label(finding: Finding) -> str:
    """Describe the verdict and how confident the analysis is about it."""
    if finding.reach is None:
        return finding.verdict.value
    status = finding.reach.status
    if status is ReachStatus.REACHABLE_CONFIRMED:
        return "reachable"
    if status is ReachStatus.REACHABLE_POSSIBLE:
        return "possibly reachable"
    if status is ReachStatus.UNREACHABLE:
        return "not reachable"
    return finding.verdict.value


def _evidence_block(finding: Finding) -> list[str]:
    reach = finding.reach
    if reach is None:
        return []
    lines = [
        f"  {finding.advisory.id}  {finding.component.name} {finding.component.version}  "
        f"{reach.status.value} ({reach.confidence.value} confidence)"
    ]
    for step in reach.shortest_path:
        location = f" {step.file}:{step.line}" if step.file and step.line else ""
        marker = " <- vulnerable symbol" if step.symbol in reach.matched_symbols else ""
        lines.append(f"      {step.symbol}{location}{marker}")
    if reach.explanation:
        lines.append(f"      {reach.explanation}")
    return lines


def _footer(results: ScanResults) -> list[str]:
    lines = [results.summary_line()]
    if results.policy is not None:
        verdict = "passed" if results.policy.passed else "FAILED"
        lines.append(f"Policy {results.policy.name}: {verdict}")
        for violation in results.policy.violations:
            lines.append(f"  {violation.message}")
    if results.advisory_snapshot_id:
        lines.append(f"Advisory snapshot {results.advisory_snapshot_id}")
    return lines


# ---------------------------------------------------------------------------
# Markdown, for pull-request comments
# ---------------------------------------------------------------------------


def render_markdown(results: ScanResults, *, show_cleared: bool = False) -> str:
    """Render results as Markdown for a pull-request comment."""
    shown = [
        finding
        for finding in results.findings
        if show_cleared or finding.verdict is not Verdict.NOT_AFFECTED
    ]
    lines = ["## Supply-chain scan", ""]

    counts = results.counts_by_verdict()
    reachable = len(results.reachable_findings())
    lines.append(
        f"**{reachable} reachable**, {counts[Verdict.UNDER_INVESTIGATION]} under "
        f"investigation, {counts[Verdict.NOT_AFFECTED]} not affected, "
        f"{len(results.findings)} total"
    )
    lines.append("")

    if not shown:
        lines.append("Nothing needs attention in this change.")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | Verdict | Advisory | Component | Fix |")
    lines.append("|---|---|---|---|---|")
    for finding in shown:
        component = f"`{finding.component.name}` {finding.component.version}"
        if not finding.component.direct:
            component += " _(transitive)_"
        fix = finding.fixed_in or "none"
        lines.append(
            f"| {finding.advisory.severity.value} | {_verdict_label(finding)} | "
            f"{finding.advisory.id} | {component} | {fix} |"
        )

    paths = [finding for finding in shown if finding.reach and finding.reach.shortest_path]
    if paths:
        lines.extend(["", "<details><summary>Call paths</summary>", ""])
        for finding in paths:
            lines.append(f"**{finding.advisory.id}** in `{finding.component.name}`")
            lines.append("")
            lines.append("```")
            lines.extend(_evidence_block(finding)[1:])
            lines.append("```")
            lines.append("")
        lines.append("</details>")

    if results.policy is not None and not results.policy.passed:
        lines.extend(["", f"Policy **{results.policy.name}** failed:"])
        for violation in results.policy.violations:
            lines.append(f"- {violation.message}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# SARIF, for GitHub code scanning
# ---------------------------------------------------------------------------


def render_sarif(results: ScanResults, *, lockfile_path: str = "unknown") -> dict[str, Any]:
    """Render results as SARIF 2.1.0.

    A dependency finding has no line of source code to point at, so each
    result is anchored to the lockfile that put the component there, which is
    both true and the file a reader would edit to fix it.
    """
    needs_attention = [
        finding for finding in results.findings if finding.verdict is not Verdict.NOT_AFFECTED
    ]

    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for finding in needs_attention:
        rule_id = finding.advisory.id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", ""),
                "shortDescription": {"text": finding.advisory.summary or rule_id},
                "fullDescription": {"text": finding.advisory.summary or rule_id},
                "help": {"text": _sarif_help(finding)},
                "properties": {
                    "security-severity": str(
                        finding.advisory.cvss_v3_score
                        if finding.advisory.cvss_v3_score is not None
                        else _severity_fallback_score(finding.advisory.severity)
                    ),
                    "tags": ["security", "supply-chain", finding.component.ecosystem],
                },
            }
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[finding.advisory.severity],
                "message": {"text": _sarif_message(finding)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": lockfile_path},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {
                    # Stable across runs so code scanning can track a finding
                    # rather than reopening it on every scan.
                    "vexpathFinding": f"{rule_id}:{finding.component.purl}"
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vexpath",
                        "version": results.core_version,
                        "informationUri": "https://github.com/",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def render_sarif_json(results: ScanResults, *, lockfile_path: str = "unknown") -> str:
    """Serialise SARIF output."""
    return json.dumps(render_sarif(results, lockfile_path=lockfile_path), indent=2) + "\n"


def _sarif_message(finding: Finding) -> str:
    parts = [f"{finding.advisory.id} affects {finding.component.name} {finding.component.version}."]
    if finding.reach is not None:
        parts.append(f"Reachability: {finding.reach.status.value}.")
        if finding.reach.explanation:
            parts.append(finding.reach.explanation)
    elif finding.verdict is Verdict.UNDER_INVESTIGATION:
        parts.append("Reachability could not be determined.")
    if finding.fixed_in:
        parts.append(f"Fixed in {finding.fixed_in}.")
    return " ".join(parts)


def _sarif_help(finding: Finding) -> str:
    if finding.fixed_in:
        return (
            f"Upgrade {finding.component.name} to {finding.fixed_in} or later. "
            f"{finding.advisory.summary}"
        )
    return f"No fixed version is known for {finding.advisory.id}. {finding.advisory.summary}"


def _severity_fallback_score(severity: Severity) -> float:
    """Approximate a numeric score where no CVSS vector was available.

    Code scanning sorts by this number, so an absent score would file a
    critical finding below a scored low one.
    """
    return {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.0,
        Severity.UNKNOWN: 5.0,
        Severity.NONE: 0.0,
    }[severity]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def group_by_component(findings: Sequence[Finding]) -> dict[str, list[Finding]]:
    """Group findings by component purl, preserving order within each group."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.component.purl, []).append(finding)
    return grouped


__all__ = [
    "group_by_component",
    "render_markdown",
    "render_sarif",
    "render_sarif_json",
    "render_text",
]
