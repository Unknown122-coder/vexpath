"""Match SBOM components against advisories.

This produces the finding set that everything downstream reasons about. Without
reachability analysis it is an ordinary dependency scanner; the verdicts it
assigns here are the starting point that reachability later refines.

The rules it follows, and why each one exists:

*Withdrawn advisories never produce a finding.* An advisory is withdrawn when
the database concludes it was wrong. Reporting it anyway is how scanners earn
their reputation for noise.

*A version that cannot be ordered is never declared safe.* Where an ecosystem's
versions cannot be compared precisely, the component is reported as needing
investigation, with a note saying so. The alternative, guessing, produces
confident answers that are sometimes wrong, which is the one outcome this
project treats as unacceptable.

*Reachability is not consulted here.* Every finding starts as `affected` or
`under_investigation`. Only the reachability stage may move a finding to
`not_affected`, and only when it has proven a path does not exist.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sscp_core.enums import (
    ComponentScope,
    Severity,
    Verdict,
    canonical_ecosystem,
    supports_reachability,
)
from sscp_core.ids import new_ulid
from sscp_core.models.advisory import Advisory, AffectedPackage
from sscp_core.models.finding import AdvisoryRef, ComponentRef, Finding
from sscp_core.models.sbom import Component, Sbom
from sscp_core.protocols import AdvisorySource
from sscp_core.purl import normalise_name
from sscp_core.versions import UnorderableVersionError, affects_version, nearest_fixed_version


@dataclass(frozen=True, slots=True)
class MatchReport:
    """The outcome of matching an SBOM against an advisory source."""

    findings: tuple[Finding, ...]
    #: Identifier of the advisory corpus used, or None if it was queried live
    #: and the result is therefore not reproducible.
    advisory_snapshot_id: str | None
    #: Components that were skipped, and why.
    skipped: tuple[str, ...] = ()
    #: Ecosystems present that reachability cannot analyse (ADR-0012).
    unsupported_reachability_ecosystems: tuple[str, ...] = ()

    @property
    def affected_count(self) -> int:
        return sum(1 for finding in self.findings if finding.verdict is Verdict.AFFECTED)

    @property
    def under_investigation_count(self) -> int:
        return sum(1 for finding in self.findings if finding.verdict is Verdict.UNDER_INVESTIGATION)


def match(
    sbom: Sbom,
    source: AdvisorySource,
    *,
    include_scopes: frozenset[ComponentScope] | None = None,
) -> MatchReport:
    """Match every component in an SBOM against the advisory source.

    Args:
        sbom: The inventory to check.
        source: Where advisories come from.
        include_scopes: Restrict matching to these scopes. Defaults to every
            scope: development dependencies are analysed and reported, and it
            is policy, not matching, that decides whether to act on them.
    """
    scopes = include_scopes or frozenset(ComponentScope)
    components = [
        component
        for component in sbom.components
        if component.scope in scopes and component.version
    ]
    skipped = [
        f"{component.purl}: no version recorded, so no advisory can be matched against it"
        for component in sbom.components
        if component.scope in scopes and not component.version
    ]

    purls = [component.purl for component in components]
    candidates = source.advisories_for(purls)

    findings: list[Finding] = []
    for component in components:
        for advisory in candidates.get(component.purl, ()):
            finding = _finding_for(component, advisory)
            if finding is not None:
                findings.append(finding)

    unsupported = tuple(
        sorted(
            {
                component.ecosystem
                for component in components
                if not supports_reachability(component.ecosystem)
            }
        )
    )

    findings.sort(key=_finding_sort_key)
    return MatchReport(
        findings=tuple(findings),
        advisory_snapshot_id=source.snapshot_id,
        skipped=tuple(skipped),
        unsupported_reachability_ecosystems=unsupported,
    )


def _finding_for(component: Component, advisory: Advisory) -> Finding | None:
    """Build a finding for one component and advisory, or None if unaffected."""
    if advisory.is_withdrawn:
        # The database has concluded this advisory was wrong. Reporting it is
        # how scanners become noise.
        return None

    package = _affected_package_for(advisory, component)
    if package is None:
        return None

    notes: list[str] = []
    try:
        is_affected = affects_version(package, component.version)
    except UnorderableVersionError as exc:
        # Cannot tell. Report it as such rather than resolve it either way: a
        # false clear hides a real vulnerability, and a false hit trains people
        # to ignore the tool.
        notes.append(
            f"Whether {component.version} falls inside this advisory's affected "
            f"range could not be determined: {exc}"
        )
        return _build(
            component,
            advisory,
            package,
            verdict=Verdict.UNDER_INVESTIGATION,
            notes=tuple(notes),
        )

    if not is_affected:
        return None

    if not supports_reachability(component.ecosystem):
        notes.append(
            f"Reachability analysis is not implemented for {component.ecosystem}, so "
            f"whether this code can execute is unknown, not cleared."
        )

    return _build(component, advisory, package, verdict=Verdict.AFFECTED, notes=tuple(notes))


def _build(
    component: Component,
    advisory: Advisory,
    package: AffectedPackage,
    *,
    verdict: Verdict,
    notes: tuple[str, ...],
) -> Finding:
    return Finding(
        id=new_ulid(),
        advisory=AdvisoryRef(
            id=advisory.id,
            summary=advisory.summary,
            severity=advisory.severity,
            cvss_v3_score=advisory.cvss_v3.base_score if advisory.cvss_v3 else None,
            cvss_v4_score=(
                advisory.cvss_v4.base_score
                if advisory.cvss_v4 and advisory.cvss_v4.base_score > 0
                else None
            ),
            epss_score=advisory.epss_score,
            kev=advisory.kev,
            aliases=advisory.aliases,
        ),
        component=ComponentRef(
            purl=component.purl,
            ecosystem=component.ecosystem,
            name=component.name,
            version=component.version,
            direct=component.direct,
            scope=component.scope,
        ),
        verdict=verdict,
        fixed_in=nearest_fixed_version(package, component.version),
        notes=notes,
    )


def _affected_package_for(advisory: Advisory, component: Component) -> AffectedPackage | None:
    """Find the advisory's entry for this component's package.

    Both sides are normalised at ingest, so this comparison should already be
    exact. It normalises again anyway, because a missed match is silent: no
    error is raised, a real vulnerability simply never appears. One redundant
    string operation per candidate is a cheap guard against that.
    """
    ecosystem = canonical_ecosystem(component.ecosystem)
    name = normalise_name(ecosystem, component.name)
    for package in advisory.affected:
        if canonical_ecosystem(package.ecosystem) != ecosystem:
            continue
        if normalise_name(ecosystem, package.name) == name:
            return package
    return None


def _finding_sort_key(finding: Finding) -> tuple[int, int, str, str]:
    """Order findings the way a reader wants them: worst first.

    Severity descending, then direct dependencies before transitive ones
    because they are actionable without an upgrade chain, then by package and
    advisory so the order is stable between runs.
    """
    severity_rank = Severity(finding.advisory.severity).rank
    return (
        -severity_rank,
        0 if finding.component.direct else 1,
        finding.component.purl,
        finding.advisory.id,
    )


def summarise_by_severity(findings: Sequence[Finding]) -> dict[Severity, int]:
    """Count findings per severity, including severities with no findings."""
    counts = dict.fromkeys(Severity, 0)
    for finding in findings:
        counts[finding.advisory.severity] += 1
    return counts


__all__ = ["MatchReport", "match", "summarise_by_severity"]
