"""Express scan conclusions as CycloneDX VEX.

The same answers as the OpenVEX document, in the other format the ecosystem
reads. Two formats rather than one because the choice is not ours: a consumer
has already picked a toolchain, and a conclusion in a format they cannot load
is a conclusion they do not have.

The formats are not equivalent, and the differences are the whole content of
this module.

**CycloneDX has its own justification vocabulary.** It does not use OpenVEX's
labels. Reachability analysis earns exactly one of its values,
``code_not_reachable``, by the same argument as in OpenVEX: the other values
assert things this project did not test.

**The analysis state answers a different question.** OpenVEX asks whether the
product is affected; CycloneDX's ``analysis.state`` asks what triage concluded.
They line up, but ``false_positive`` is deliberately never produced. A finding
that does not apply because the code cannot run is not a mistake in the
advisory, and labelling it one would blame the advisory database for being
right.

**A CycloneDX VEX document carries the affected components inline.** Each
vulnerability names the components it affects by their bom-ref, so the document
is readable without the SBOM beside it. Which means the components appear
twice, once as the inventory and once as a reference, and the two must agree
or a consumer resolves a reference to nothing.

Deterministic, like every other document this project writes: the same results
produce the same bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from vexpath_core import __version__ as core_version
from vexpath_core.enums import CycloneDxAnalysisState, ReachStatus, Severity, Verdict
from vexpath_core.models.finding import Finding
from vexpath_core.models.results import ScanResults
from vexpath_core.sbom.cyclonedx import WRITE_VERSION

#: CycloneDX's justification vocabulary, which is not OpenVEX's. Only the one
#: reachability earns is named here; the rest are listed in the specification
#: and each asserts something this project does not test.
CODE_NOT_REACHABLE = "code_not_reachable"

#: Our verdict to CycloneDX's triage state. ``false_positive`` is deliberately
#: absent: a finding that does not apply because the code cannot run is not an
#: error in the advisory.
_STATE: dict[Verdict, CycloneDxAnalysisState] = {
    Verdict.AFFECTED: CycloneDxAnalysisState.EXPLOITABLE,
    Verdict.NOT_AFFECTED: CycloneDxAnalysisState.NOT_AFFECTED,
    Verdict.UNDER_INVESTIGATION: CycloneDxAnalysisState.IN_TRIAGE,
    Verdict.FIXED: CycloneDxAnalysisState.RESOLVED,
}

#: CycloneDX severity values. Its vocabulary is lower-case and has no
#: "UNKNOWN", using "unknown" instead.
_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.UNKNOWN: "unknown",
}


class CycloneDxVexError(Exception):
    """Raised when results cannot be expressed as CycloneDX VEX."""


@dataclass(frozen=True, slots=True)
class VexMetadata:
    """Who produced the document, and what it is about."""

    author: str
    #: Purl or bom-ref of the product. The vulnerable dependencies are its
    #: components, never the subject of the statement themselves.
    product_id: str | None = None


def render(results: ScanResults, metadata: VexMetadata) -> dict[str, Any]:
    """Build a CycloneDX 1.6 VEX document from one scan's results.

    Raises:
        CycloneDxVexError: if a finding would need a justification this
            analysis did not establish.
    """
    if not metadata.author.strip():
        msg = (
            "a VEX document needs an author: a consumer decides whether to "
            "believe it by who stands behind it"
        )
        raise CycloneDxVexError(msg)

    product = metadata.product_id or (
        f"pkg:generic/{results.project.slug}"
        if results.project.slug
        else "urn:vexpath:product:unidentified"
    )
    timestamp = results.generated_at.isoformat().replace("+00:00", "Z")

    components = _components(results)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": WRITE_VERSION,
        "serialNumber": _serial(results),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [{"type": "application", "name": "vexpath", "version": core_version}]
            },
            "component": {"type": "application", "bom-ref": product, "name": product},
            "authors": [{"name": metadata.author.strip()}],
        },
        # The affected components, inline, so the document is readable without
        # the SBOM beside it. Every bom-ref a vulnerability points at is here.
        "components": components,
        "vulnerabilities": [
            _vulnerability(finding, timestamp, results) for finding in _ordered(results.findings)
        ],
    }


def render_json(results: ScanResults, metadata: VexMetadata, *, indent: int | None = 2) -> str:
    """Serialise a document deterministically."""
    return json.dumps(render(results, metadata), indent=indent, sort_keys=False) + "\n"


def _ordered(findings: tuple[Finding, ...]) -> list[Finding]:
    """Worst first, then stable on identifiers."""
    return sorted(
        findings,
        key=lambda finding: (
            -finding.advisory.severity.rank,
            finding.advisory.id,
            finding.component.purl,
        ),
    )


def _components(results: ScanResults) -> list[dict[str, Any]]:
    """The components any vulnerability refers to, deduplicated.

    Only the ones a vulnerability points at. A full inventory belongs in an
    SBOM; repeating it here would make the VEX document a worse copy of one.
    """
    seen: dict[str, dict[str, Any]] = {}
    for finding in _ordered(results.findings):
        component = finding.component
        seen.setdefault(
            component.purl,
            {
                "type": "library",
                "bom-ref": component.purl,
                "name": component.name,
                "version": component.version,
                "purl": component.purl,
            },
        )
    return list(seen.values())


def _vulnerability(finding: Finding, timestamp: str, results: ScanResults) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "bom-ref": f"{finding.advisory.id}:{finding.component.purl}",
        "id": finding.advisory.id,
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{finding.advisory.id}"},
        "ratings": _ratings(finding),
        "analysis": _analysis(finding, results),
        "affects": [{"ref": finding.component.purl}],
        "updated": timestamp,
    }
    if finding.advisory.summary:
        entry["description"] = finding.advisory.summary
    if finding.advisory.aliases:
        entry["references"] = [
            {
                "id": alias,
                "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{alias}"},
            }
            for alias in finding.advisory.aliases
        ]
    return entry


def _ratings(finding: Finding) -> list[dict[str, Any]]:
    """Severity, and the score behind it when there is one.

    A rating with no score still carries the severity, because a consumer
    filtering on severity should not lose a finding for want of a number.
    """
    rating: dict[str, Any] = {
        "severity": _SEVERITY[finding.advisory.severity],
        "source": {"name": "OSV"},
    }
    if finding.advisory.cvss_v3_score is not None:
        rating["score"] = finding.advisory.cvss_v3_score
        rating["method"] = "CVSSv31"
    return [rating]


def _analysis(finding: Finding, results: ScanResults) -> dict[str, Any]:
    """What triage concluded, and the evidence for it.

    ``detail`` carries the reachability explanation. The specification does not
    require it, and a consumer deciding whether to trust someone else's
    "not affected" has nothing to go on without it.
    """
    analysis: dict[str, Any] = {"state": _STATE[finding.verdict].value}

    if finding.verdict is Verdict.NOT_AFFECTED:
        analysis["justification"] = _justification(finding)
    if finding.verdict is Verdict.AFFECTED:
        # The specification's response vocabulary. "update" is the honest
        # answer when a fixed version exists; otherwise the work is not an
        # upgrade and saying so would mislead.
        analysis["response"] = ["update"] if finding.fixed_in else ["will_not_fix"]

    analysis["detail"] = _detail(finding, results)
    return analysis


def _justification(finding: Finding) -> str:
    """The CycloneDX justification for a cleared finding.

    The vocabulary is not OpenVEX's, and only one of its values is earned by
    reachability analysis. The others assert that the code is absent, that
    configuration or an environment is required, or that something protects
    it, and this project tested none of those.
    """
    if finding.reach is None or finding.reach.status is not ReachStatus.UNREACHABLE:
        if finding.suppressed_by is not None:
            # A person asserted this and stands behind it. The detail says who.
            return CODE_NOT_REACHABLE
        msg = (
            f"{finding.advisory.id} on {finding.component.name} is cleared without "
            f"a proven-unreachable result, which is the only thing this analysis "
            f"can justify"
        )
        raise CycloneDxVexError(msg)
    return CODE_NOT_REACHABLE


def _detail(finding: Finding, results: ScanResults) -> str:
    """The evidence, in the one free-text field the format gives."""
    parts: list[str] = []
    reach = finding.reach
    if reach is None:
        parts.append(
            "Reachability analysis did not run for this finding, so whether the "
            "vulnerable code can execute is unknown rather than cleared."
        )
    else:
        parts.append(reach.explanation.strip())
        if reach.searched_symbols:
            shown = ", ".join(reach.searched_symbols[:5])
            more = (
                f" and {len(reach.searched_symbols) - 5} more"
                if len(reach.searched_symbols) > 5
                else ""
            )
            parts.append(f"Searched for: {shown}{more}.")
        if reach.entry_points is not None:
            parts.append(
                f"Searched from {reach.entry_points.count} entry point(s), "
                f"identified by {reach.entry_points.source.value}."
            )
        parts.append(f"Confidence: {reach.confidence.value}.")

    if finding.suppressed_by is not None:
        parts.append(f"Suppressed by {finding.suppressed_by}.")
    if finding.fixed_in:
        parts.append(f"Fixed in {finding.component.name} {finding.fixed_in}.")
    parts.append(
        f"Advisory corpus: snapshot {results.advisory_snapshot_id}."
        if results.advisory_snapshot_id
        else "Advisories were read live, so this conclusion is not reproducible."
    )
    return " ".join(parts)


def _serial(results: ScanResults) -> str:
    """A serial number derived from the content.

    Derived rather than random, so re-running a scan of an unchanged project
    produces the same document and two can be compared.
    """
    import hashlib
    import uuid

    material = "|".join(
        [
            results.advisory_snapshot_id or "live",
            results.generated_at.isoformat(),
            *(
                f"{finding.advisory.id}:{finding.component.purl}:{finding.verdict.value}"
                for finding in _ordered(results.findings)
            ),
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    return f"urn:uuid:{uuid.UUID(bytes=digest[:16], version=4)}"


def validate(text: str) -> None:
    """Check a document against the official CycloneDX schema.

    Raises:
        CycloneDxVexError: with the schema's own message when it does not fit.
    """
    from vexpath_core.sbom.cyclonedx import CycloneDxError
    from vexpath_core.sbom.cyclonedx import validate as validate_document

    try:
        validate_document(text)
    except CycloneDxError as exc:
        raise CycloneDxVexError(str(exc)) from exc


def state_counts(document: dict[str, Any]) -> dict[str, int]:
    """How many vulnerabilities are in each analysis state."""
    counts: dict[str, int] = {}
    for entry in document.get("vulnerabilities", []):
        state = str((entry.get("analysis") or {}).get("state") or "unknown")
        counts[state] = counts.get(state, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "CODE_NOT_REACHABLE",
    "CycloneDxVexError",
    "VexMetadata",
    "render",
    "render_json",
    "state_counts",
    "validate",
]
