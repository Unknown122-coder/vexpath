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
from dataclasses import field as dataclass_field

from vexpath_core.enums import (
    ComponentScope,
    Severity,
    Verdict,
    canonical_ecosystem,
    supports_reachability,
)
from vexpath_core.ids import new_ulid
from vexpath_core.models.advisory import Advisory, AffectedPackage
from vexpath_core.models.finding import AdvisoryRef, ComponentRef, Finding
from vexpath_core.models.sbom import Component, Sbom
from vexpath_core.protocols import AdvisorySource
from vexpath_core.purl import normalise_name
from vexpath_core.versions import UnorderableVersionError, affects_version, nearest_fixed_version


@dataclass(frozen=True, slots=True)
class MatchReport:
    """The outcome of matching an SBOM against an advisory source."""

    findings: tuple[Finding, ...]
    #: Identifier of the advisory corpus used, or None if it was queried live
    #: and the result is therefore not reproducible.
    advisory_snapshot_id: str | None
    #: The full advisory behind each finding, keyed by finding id. The
    #: reachability stage needs the vulnerable symbols, which a finding carries
    #: no room for, and re-querying the source for them would be wasteful and
    #: could read a different corpus.
    advisories: dict[str, Advisory] = dataclass_field(default_factory=dict)
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
    behind: dict[str, Advisory] = {}
    # One finding per advisory per component, enforced here rather than
    # assumed of the source. A finding is a statement about one
    # vulnerability in one installed package: the same statement twice is
    # not extra information, it is a wrong count. It happened -- OSV returns
    # both the GHSA and the PYSEC record for a PyPI vulnerability and both
    # are named by their shared CVE -- and the symptom was every number this
    # tool printed being exactly double.
    seen: set[tuple[str, str]] = set()
    for component in components:
        for advisory in candidates.get(component.purl, ()):
            key = (advisory.id, component.purl)
            if key in seen:
                continue
            finding = finding_for(component, advisory)
            if finding is not None:
                seen.add(key)
                findings.append(finding)
                behind[finding.id] = advisory

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
        advisories=behind,
        skipped=tuple(skipped),
        unsupported_reachability_ecosystems=unsupported,
    )


def finding_for(component: Component, advisory: Advisory) -> Finding | None:
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


def probe_finding(component: Component, advisory: Advisory) -> Finding:
    """Build a finding for a component the advisory does not currently affect.

    Used only by triage, to answer "would this reach my code if I were on an
    affected version". It never enters a scan's finding set, and it is created
    as ``under_investigation`` rather than ``affected`` so that it cannot be
    mistaken for a real match if it ever leaks into one.

    Raises:
        ValueError: if the advisory has no entry for this component's package,
            in which case there is nothing to probe.
    """
    package = _affected_package_for(advisory, component)
    if package is None:
        msg = f"{advisory.id} has no affected entry for {component.purl}"
        raise ValueError(msg)
    return _build(
        component,
        advisory,
        package,
        verdict=Verdict.UNDER_INVESTIGATION,
        notes=(
            f"{component.name} {component.version} is outside this advisory's "
            f"affected range; this record exists only to explain reachability.",
        ),
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


__all__ = [
    "MatchReport",
    "finding_for",
    "match",
    "probe_finding",
    "summarise_by_severity",
]
