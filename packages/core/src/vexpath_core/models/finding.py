"""Findings and reachability results.

A finding is one (component, advisory) pair together with the verdict and the
evidence for it. The invariant enforced here is the product's central promise:
a finding is never marked ``not_affected`` on the strength of uncertainty.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from vexpath_core.enums import (
    ComponentScope,
    Confidence,
    EdgeKind,
    EntryPointSource,
    ReachReason,
    ReachStatus,
    Severity,
    Verdict,
    VexJustification,
)
from vexpath_core.models.common import Base


class AdvisoryRef(Base):
    """The advisory fields a finding carries inline.

    Severity and exploitability are copied at scan time rather than read
    through a join, because advisories change and a historical scan must keep
    reporting what it actually concluded.
    """

    id: str
    summary: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v4_score: float | None = Field(default=None, ge=0.0, le=10.0)
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    kev: bool = False
    aliases: tuple[str, ...] = ()


class ComponentRef(Base):
    """The component fields a finding carries inline."""

    purl: str
    ecosystem: str
    name: str
    version: str
    direct: bool = False
    scope: ComponentScope = ComponentScope.RUNTIME


class CallPathStep(Base):
    """One hop on the path from an entry point to a vulnerable symbol."""

    symbol: str
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    #: How the edge *into* this symbol was resolved. A single ``dynamic`` or
    #: ``opaque`` hop is what separates a confirmed path from a possible one.
    edge_kind: EdgeKind = EdgeKind.STATIC


class GraphStats(Base):
    """Quality measures for the call graph a verdict was derived from.

    Published with every result so a reader can judge how much the graph could
    see, instead of having to trust the verdict blindly.
    """

    first_party_nodes: int = Field(default=0, ge=0)
    first_party_edges: int = Field(default=0, ge=0)
    linked_packages: int = Field(default=0, ge=0)
    #: Share of call sites whose callee could not be resolved. The single best
    #: indicator of how much this graph should be trusted.
    unresolved_call_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    parse_error_files: int = Field(default=0, ge=0)
    parse_error_ratio: float = Field(default=0.0, ge=0.0, le=1.0)


class EntryPointInfo(Base):
    """The entry points a reachability search started from."""

    source: EntryPointSource
    count: int = Field(ge=0)
    items: tuple[str, ...] = ()


class ReachabilityResult(Base):
    """The outcome of searching for a path to an advisory's vulnerable symbols."""

    status: ReachStatus
    confidence: Confidence
    #: Why a non-definitive status was reached. Required whenever the status is
    #: not a plain reachable or unreachable answer, so no result is unexplained.
    reason: ReachReason | None = None
    #: Vulnerable symbols that the search actually arrived at.
    matched_symbols: tuple[str, ...] = ()
    #: Every symbol that was looked for. An unreachable verdict means nothing
    #: without saying what was searched.
    searched_symbols: tuple[str, ...] = ()
    shortest_path: tuple[CallPathStep, ...] = ()
    path_count: int = Field(default=0, ge=0)
    #: True when every path found depends on a conservatively resolved call.
    via_dynamic_edges: bool = False
    entry_points: EntryPointInfo | None = None
    graph_stats: GraphStats | None = None
    #: Human-readable summary, rendered into reports, VEX impact statements and
    #: the web UI from the same text.
    explanation: str = ""

    @model_validator(mode="after")
    def _check_consistency(self) -> ReachabilityResult:
        if self.status.is_reachable and not self.matched_symbols:
            msg = "a reachable result must name the symbols it reached"
            raise ValueError(msg)
        if self.status is ReachStatus.UNREACHABLE and not self.searched_symbols:
            msg = "an unreachable result must name the symbols it searched for"
            raise ValueError(msg)
        if (
            self.status in {ReachStatus.SYMBOLS_UNKNOWN, ReachStatus.GRAPH_INCOMPLETE}
            and self.reason is None
        ):
            msg = f"status {self.status.value} requires a reason"
            raise ValueError(msg)
        if self.status is ReachStatus.REACHABLE_POSSIBLE and not self.via_dynamic_edges:
            msg = "reachable_possible means the path relied on a dynamic or opaque edge"
            raise ValueError(msg)
        return self


class Finding(Base):
    """One advisory affecting one component, with its verdict and evidence."""

    id: str
    advisory: AdvisoryRef
    component: ComponentRef
    verdict: Verdict
    #: Nearest version that fixes the advisory, when one exists.
    fixed_in: str | None = None
    justification: VexJustification | None = None
    reach: ReachabilityResult | None = None
    #: Scan in which this finding first appeared, which gives ``age_days``.
    first_seen_scan_id: str | None = None
    age_days: int | None = Field(default=None, ge=0)
    #: Identifier of a manual suppression, when one applies. A suppression
    #: changes the policy outcome, never the analytical verdict.
    suppressed_by: str | None = None
    #: Caveats about how this finding was produced, in plain language. Used
    #: where matching itself was uncertain, for instance when an ecosystem's
    #: versions cannot be ordered precisely, so a reader is never left to
    #: assume more precision than the analysis had.
    notes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_verdict_is_supported(self) -> Finding:
        if self.verdict is Verdict.NOT_AFFECTED:
            if self.justification is None:
                msg = "a not_affected verdict requires an OpenVEX justification"
                raise ValueError(msg)
            # The core promise: only proven unreachability may clear a finding.
            # A manual suppression is the one exception, and it is recorded.
            if (
                self.reach is not None
                and not self.reach.status.may_suppress
                and self.suppressed_by is None
            ):
                msg = (
                    f"cannot mark {self.advisory.id} not_affected from reachability status "
                    f"{self.reach.status.value}; only 'unreachable' may suppress a finding"
                )
                raise ValueError(msg)
        elif self.justification is not None:
            msg = "justification applies only to a not_affected verdict"
            raise ValueError(msg)
        return self

    @property
    def is_reachable(self) -> bool:
        return self.reach is not None and self.reach.status.is_reachable

    @property
    def needs_attention(self) -> bool:
        """True when this finding is not cleared, so a human should look."""
        return self.verdict in {Verdict.AFFECTED, Verdict.UNDER_INVESTIGATION}


__all__ = [
    "AdvisoryRef",
    "CallPathStep",
    "ComponentRef",
    "EntryPointInfo",
    "Finding",
    "GraphStats",
    "ReachabilityResult",
]
