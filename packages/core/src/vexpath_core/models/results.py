"""The ``vexpath.results`` document: what a scan produces.

This is the contract between the CLI, the GitHub Action, the platform API and
anyone else who wants to consume our output. It is versioned by the ``schema``
field and published as JSON Schema, so it can be relied on.
"""

from __future__ import annotations

from collections import Counter

from pydantic import AwareDatetime, Field

from vexpath_core.enums import SbomFormat, ScanMode, Severity, Verdict
from vexpath_core.models.common import Base
from vexpath_core.models.finding import EntryPointInfo, Finding, GraphStats


class ProjectRef(Base):
    """What was scanned."""

    slug: str | None = None
    git_ref: str | None = None
    git_sha: str | None = None


class SbomRef(Base):
    """The SBOM the findings were derived from."""

    format: SbomFormat
    sha256: str
    component_count: int = Field(ge=0)


class PolicyViolation(Base):
    """One reason a policy failed."""

    message: str
    finding_id: str | None = None
    advisory_id: str | None = None


class PolicyResult(Base):
    """The outcome of evaluating a policy against the findings."""

    name: str
    #: False means the build should fail.
    passed: bool
    violations: tuple[PolicyViolation, ...] = ()


class ArtifactPaths(Base):
    """Where the scan wrote its documents, relative to the output directory."""

    sbom: str | None = None
    openvex: str | None = None
    cdx_vex: str | None = None
    attestation: str | None = None


class ScanResults(Base):
    """Everything one scan concluded."""

    #: Schema identifier, for example ``vexpath.results/1``. Aliased because
    #: ``schema`` collides with an attribute name on the model base class.
    schema_version: str = Field(alias="schema", serialization_alias="schema")
    #: Version of the analysis core that produced these verdicts.
    core_version: str
    generated_at: AwareDatetime
    mode: ScanMode = ScanMode.CLI
    project: ProjectRef = ProjectRef()
    sbom: SbomRef | None = None
    #: Identifier of the advisory snapshot used. ``None`` means the advisories
    #: were read live, so this scan is not exactly reproducible.
    advisory_snapshot_id: str | None = None
    entry_points: EntryPointInfo | None = None
    graph: GraphStats | None = None
    findings: tuple[Finding, ...] = ()
    policy: PolicyResult | None = None
    artifacts: ArtifactPaths = ArtifactPaths()
    #: Ecosystems present whose components could not be analysed for
    #: reachability, so reports can say so plainly rather than let a reader
    #: assume "under investigation" means "checked".
    unsupported_reachability_ecosystems: tuple[str, ...] = ()
    #: Limitations of this particular run, in plain language: dependencies
    #: whose source was unavailable, caches that were cold, graphs that were
    #: incomplete. Separate from the ecosystem list because "we do not support
    #: this language" and "we could not find this package" are different facts
    #: and a reader needs to tell them apart.
    analysis_notes: tuple[str, ...] = ()

    @property
    def is_reproducible(self) -> bool:
        return self.advisory_snapshot_id is not None

    def counts_by_verdict(self) -> dict[Verdict, int]:
        counts = Counter(f.verdict for f in self.findings)
        return {verdict: counts.get(verdict, 0) for verdict in Verdict}

    def counts_by_severity(self, *, verdict: Verdict | None = None) -> dict[Severity, int]:
        selected = (
            self.findings if verdict is None else [f for f in self.findings if f.verdict is verdict]
        )
        counts = Counter(f.advisory.severity for f in selected)
        return {severity: counts.get(severity, 0) for severity in Severity}

    def reachable_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.is_reachable)

    def findings_needing_attention(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.needs_attention)

    def summary_line(self) -> str:
        """One-line summary, used in the badge, the PR comment and the CLI tail."""
        by_verdict = self.counts_by_verdict()
        reachable = len(self.reachable_findings())
        return (
            f"{len(self.findings)} findings | "
            f"{reachable} reachable | "
            f"{by_verdict[Verdict.NOT_AFFECTED]} not affected | "
            f"{by_verdict[Verdict.UNDER_INVESTIGATION]} under investigation"
        )


__all__ = [
    "ArtifactPaths",
    "PolicyResult",
    "PolicyViolation",
    "ProjectRef",
    "SbomRef",
    "ScanResults",
]
