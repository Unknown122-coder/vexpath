"""Generate OpenVEX documents from scan results.

This is what the whole analysis exists to produce. A scan's verdicts live in
this project's own result format; a VEX document is the same conclusions in a
form other people's tools consume, which is the difference between an opinion
and an artefact.

Three modelling decisions shape the output, and the first is the one most
tools get wrong.

**A VEX statement is about your product, not about the dependency.** The
subject of "not affected" is the thing you ship. The vulnerable dependency is a
*subcomponent* of it. Publishing a statement whose product is
``pkg:pypi/urllib3@1.26.17`` says "urllib3 is not affected by its own
advisory", which is both false and not yours to say. So the product is the
project being scanned and every finding's component is a subcomponent, exactly
as the specification intends.

**A ``not_affected`` status needs a justification the specification recognises,
and only one of them is ours to use.** Reachability analysis establishes that
the vulnerable code is not in the execute path. It does not establish that the
component is absent, that the vulnerable code was removed, that an adversary
cannot reach it, or that a mitigation is in place. Those are different claims
with different evidence, and asserting one we did not test would make the
document worse than silence.

**Every statement carries the evidence as an impact statement.** The
specification allows a bare justification; a reader deciding whether to trust a
clearance needs the call path, the entry-point count and the symbols searched
for. An unexplained clearance is one nobody can check.

The document is deterministic: the same results produce the same bytes, so a
VEX document can be diffed between scans and its hash can be attested.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from vexpath_core import __version__ as core_version
from vexpath_core.enums import ReachStatus, Verdict, VexJustification
from vexpath_core.models.finding import Finding
from vexpath_core.models.results import ScanResults

#: The specification version this generator emits. Part of the document and of
#: the attestation predicate type, so it is named once.
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

#: Predicate type for an in-toto statement carrying one of these documents.
OPENVEX_PREDICATE_TYPE = "https://openvex.dev/ns/v0.2.0"

#: The only justification reachability analysis earns. Declared as a constant
#: because using any other would be a claim this project did not test.
EARNED_JUSTIFICATION = VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH

#: Statuses OpenVEX defines. Ours is deliberately the same vocabulary, so the
#: mapping is identity and a new verdict cannot silently become the wrong
#: status.
_STATUS: dict[Verdict, str] = {
    Verdict.AFFECTED: "affected",
    Verdict.NOT_AFFECTED: "not_affected",
    Verdict.UNDER_INVESTIGATION: "under_investigation",
    Verdict.FIXED: "fixed",
}


class VexError(Exception):
    """Raised when results cannot be expressed as a VEX document."""


@dataclass(frozen=True, slots=True)
class VexIdentity:
    """Who is making these statements, and about what.

    A VEX document with no identifiable author is not usable: its whole purpose
    is that a consumer can decide whether to believe it, and that decision is
    about who signed it.
    """

    #: The author, as an organisation or a person. Required.
    author: str
    #: Role, as the specification's free-text field.
    role: str = "Software supply-chain analysis"
    #: Purl or other identifier of the product these statements describe. When
    #: omitted, the project slug is used, and failing that a placeholder that
    #: says plainly it needs setting.
    product_id: str | None = None


def render(
    results: ScanResults,
    identity: VexIdentity,
    *,
    document_id: str | None = None,
    version: int = 1,
    include_under_investigation: bool = True,
) -> dict[str, Any]:
    """Build an OpenVEX document from one scan's results.

    Args:
        results: What the scan concluded.
        identity: Who is speaking, and about which product.
        document_id: Document identifier. Derived from the content when
            omitted, which keeps the document deterministic.
        version: Document version, incremented by the publisher when a later
            document supersedes this one for the same product.
        include_under_investigation: Emit statements for findings still being
            analysed. On by default: "we are looking at this" is a useful
            thing to publish, and its absence would be read as "not an issue".

    Raises:
        VexError: if a finding cannot be expressed without making a claim the
            analysis did not establish.
    """
    if not identity.author.strip():
        msg = "a VEX document needs an author: a consumer decides whether to believe it by who signed it"
        raise VexError(msg)

    product = _product_id(results, identity)
    timestamp = results.generated_at.isoformat()

    statements: list[dict[str, Any]] = []
    for finding in _ordered(results.findings):
        if finding.verdict is Verdict.UNDER_INVESTIGATION and not include_under_investigation:
            continue
        statements.append(_statement(finding, product, timestamp, results))

    document = {
        "@context": OPENVEX_CONTEXT,
        "author": identity.author,
        "role": identity.role,
        "timestamp": timestamp,
        "version": version,
        "tooling": f"vexpath/{core_version}",
        "statements": statements,
    }
    # Derived last, from the document without an identifier, so the same
    # results always produce the same identifier.
    document["@id"] = document_id or _derive_id(document)
    return document


def render_json(
    results: ScanResults,
    identity: VexIdentity,
    **kwargs: Any,
) -> str:
    """Render a document as deterministic JSON.

    Sorted keys and a fixed separator, so two scans of an unchanged project
    produce byte-identical documents. That is what lets a VEX document be
    diffed and what makes its hash worth attesting.
    """
    document = render(results, identity, **kwargs)
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _ordered(findings: tuple[Finding, ...]) -> list[Finding]:
    """Order statements stably, worst first.

    The result order is already severity-descending, but it is re-sorted on
    identifiers here so a document does not change because two findings of
    equal severity were discovered in a different order.
    """
    return sorted(
        findings,
        key=lambda finding: (
            -finding.advisory.severity.rank,
            finding.advisory.id,
            finding.component.purl,
        ),
    )


def _product_id(results: ScanResults, identity: VexIdentity) -> str:
    if identity.product_id:
        return identity.product_id
    if results.project.slug:
        return f"pkg:generic/{results.project.slug}"
    # Said plainly rather than invented: a product identifier nobody set is
    # a document nobody can match against their inventory.
    return "urn:vexpath:product:unidentified"


def _statement(
    finding: Finding, product: str, timestamp: str, results: ScanResults
) -> dict[str, Any]:
    """One statement, with the evidence a reader needs to check it."""
    status = _STATUS[finding.verdict]
    statement: dict[str, Any] = {
        "vulnerability": _vulnerability(finding),
        "timestamp": timestamp,
        "products": [
            {
                "@id": product,
                # The vulnerable dependency is a subcomponent of the product.
                # Making it the product instead would be a statement about
                # someone else's package.
                "subcomponents": [{"@id": finding.component.purl}],
            }
        ],
        "status": status,
    }

    if finding.verdict is Verdict.NOT_AFFECTED:
        statement["justification"] = _justification(finding)
        statement["impact_statement"] = _impact(finding, results)
    elif finding.verdict is Verdict.AFFECTED:
        statement["action_statement"] = _action(finding)
        statement["action_statement_timestamp"] = timestamp
    elif finding.verdict is Verdict.UNDER_INVESTIGATION:
        statement["status_notes"] = _status_notes(finding)
    return statement


def _vulnerability(finding: Finding) -> dict[str, Any]:
    vulnerability: dict[str, Any] = {"name": finding.advisory.id}
    if finding.advisory.aliases:
        vulnerability["aliases"] = list(finding.advisory.aliases)
    if finding.advisory.summary:
        vulnerability["description"] = finding.advisory.summary
    return vulnerability


def _justification(finding: Finding) -> str:
    """The justification for a cleared finding.

    Refuses anything but the one reachability establishes. A finding cleared
    by a human suppression carries its own justification, and that is the only
    other case: a justification nobody tested would make the document worse
    than silence.
    """
    if finding.suppressed_by is not None and finding.justification is not None:
        return str(finding.justification.value)
    if finding.justification is not EARNED_JUSTIFICATION:
        msg = (
            f"{finding.advisory.id} on {finding.component.name} is cleared with "
            f"justification {finding.justification!r}, which reachability "
            f"analysis does not establish"
        )
        raise VexError(msg)
    return str(EARNED_JUSTIFICATION.value)


def _impact(finding: Finding, results: ScanResults) -> str:
    """Why this finding does not apply, in terms a reader can check.

    The specification would accept the justification alone. A consumer
    deciding whether to trust someone else's "not affected" needs to see what
    was searched for and from where, so all of it goes in.
    """
    reach = finding.reach
    if reach is None:
        return (
            f"{finding.component.name} {finding.component.version} is present, and "
            f"this finding was cleared without reachability evidence."
        )

    parts = [reach.explanation.strip()]
    if reach.searched_symbols:
        parts.append(
            "Searched for: "
            + ", ".join(reach.searched_symbols[:8])
            + (
                f" and {len(reach.searched_symbols) - 8} more"
                if len(reach.searched_symbols) > 8
                else ""
            )
            + "."
        )
    if reach.entry_points is not None:
        parts.append(
            f"Searched from {reach.entry_points.count} entry point(s), "
            f"identified by {reach.entry_points.source.value}."
        )
    if reach.graph_stats is not None:
        stats = reach.graph_stats
        parts.append(
            f"The call graph held {stats.first_party_nodes} first-party symbols "
            f"and {stats.linked_packages} linked dependency package(s), with "
            f"{stats.unresolved_call_ratio:.1%} of call sites unresolved."
        )
    parts.append(f"Confidence: {reach.confidence.value}.")
    if results.advisory_snapshot_id:
        parts.append(f"Advisory corpus: snapshot {results.advisory_snapshot_id}.")
    else:
        parts.append("Advisories were read live, so this conclusion is not reproducible.")
    return " ".join(parts)


def _action(finding: Finding) -> str:
    """What to do about a finding that applies.

    Required by the specification for an affected status, and the only field
    in the document that tells someone what to actually do.
    """
    upgrade = (
        f"Upgrade {finding.component.name} to {finding.fixed_in} or later."
        if finding.fixed_in
        else (
            f"No fixed version of {finding.component.name} is published yet; "
            f"remove it, pin away from the affected range, or mitigate in place."
        )
    )
    if finding.reach is None:
        return upgrade

    if finding.reach.status is ReachStatus.REACHABLE_POSSIBLE:
        return (
            f"{upgrade} Every path found depends on a call this analysis could not "
            f"resolve precisely, so treat it as reachable until shown otherwise."
        )
    path = " -> ".join(step.symbol for step in finding.reach.shortest_path)
    if path:
        return f"{upgrade} The vulnerable code is reached by: {path}."
    return upgrade


def _status_notes(finding: Finding) -> str:
    """Why a finding is still open.

    This is the field that stops "under investigation" being read as a shrug.
    A reader needs to know whether nobody has looked or whether something
    specific prevented an answer.
    """
    reach = finding.reach
    if reach is None:
        return (
            "Reachability analysis did not run for this finding, so whether the "
            "vulnerable code can execute is unknown rather than cleared."
        )
    note = reach.explanation.strip()
    if reach.reason is not None:
        note += f" Reason: {reach.reason.value}."
    return note


def _derive_id(document: dict[str, Any]) -> str:
    """A content-addressed identifier.

    Derived rather than random so that re-running a scan of an unchanged
    project produces the same document, which is what allows two documents to
    be compared at all.
    """
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"https://openvex.dev/docs/vexpath-{digest[:32]}"


def statement_counts(document: dict[str, Any]) -> dict[str, int]:
    """How many statements of each status a document carries."""
    counts: dict[str, int] = {}
    for statement in document.get("statements", []):
        status = str(statement.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def document_sha256(rendered: str) -> str:
    """The digest an attestation signs."""
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


__all__ = [
    "EARNED_JUSTIFICATION",
    "OPENVEX_CONTEXT",
    "OPENVEX_PREDICATE_TYPE",
    "VexError",
    "VexIdentity",
    "document_sha256",
    "render",
    "render_json",
    "statement_counts",
]
