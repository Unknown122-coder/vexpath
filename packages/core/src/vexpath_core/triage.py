"""Triage one advisory against one project.

``vexpath scan`` answers "what should I act on" across a whole inventory. This
answers the question that follows it, and the one people actually argue about:
*why* did that single advisory come out the way it did, and what in my code is
responsible.

It exists because a verdict nobody can check is a verdict nobody will trust.
The scan report has room for one path per finding; triage has room for all the
evidence: which symbols were searched for and where they came from, which of
them exist in the installed version, which entry points reach them and which do
not, and what the graph looked like.

Two rules shape the design.

**It must agree with the scan.** Triage and scan build the same graph through
the same ``prepare_reachability``, so a disagreement between them is impossible
rather than merely unlikely. A triage tool that contradicts the report it is
explaining is worse than no triage tool.

**It reports, it does not clear.** Nothing here writes VEX or changes a scan's
stored verdict. An operator may name a symbol by hand with ``extra_symbols``,
which is useful when an advisory carries no fix commit, but such a symbol is
recorded as manually supplied and carries low confidence, because the tool
cannot check that the fix really touched it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from vexpath_core.enums import (
    Confidence,
    EntryPointSource,
    ReachStatus,
    Severity,
    SymbolKind,
    SymbolSource,
    Verdict,
)
from vexpath_core.models.advisory import Advisory, VulnerableSymbol
from vexpath_core.models.finding import CallPathStep, Finding, GraphStats, ReachabilityResult
from vexpath_core.models.sbom import Component
from vexpath_core.protocols import AdvisorySource, Clock, SystemClock
from vexpath_core.reach.graph import expand_targets, search
from vexpath_core.reach.verdict import decide
from vexpath_core.scan import (
    ReachabilitySetup,
    ScanOptions,
    build_inventory,
    prepare_reachability,
)
from vexpath_core.vulnmatch import finding_for, probe_finding

#: Each entry point reaching a symbol is explained separately, because "it is
#: reachable from your web handler" and "it is reachable from a one-off script"
#: call for different responses. The public-function fallback can produce
#: hundreds of them, so the explanation stops here and the rest are counted.
MAX_ENTRY_POINTS_EXPLAINED = 25


class TriageError(Exception):
    """Raised when the advisory cannot be triaged at all."""


@dataclass(frozen=True, slots=True)
class SymbolProbe:
    """One symbol the search looked for, and what became of it."""

    symbol: str
    kind: SymbolKind
    source: SymbolSource
    confidence: Confidence
    #: Defined in a linked call graph, so paths through it can be traversed.
    defined: bool
    #: Named by some call the analysis saw, even if its definition is invisible.
    referenced: bool
    status: str = "unreached"

    @property
    def missing(self) -> bool:
        """Neither defined nor referenced anywhere.

        Usually means the symbol was renamed between the fixed version and the
        installed one, which is why an absence of paths to it proves nothing.
        """
        return not self.defined and not self.referenced


@dataclass(frozen=True, slots=True)
class EntryPointReach:
    """Whether one entry point reaches the vulnerable code, and how."""

    entry_point: str
    #: ``"certain"``, ``"possible"`` or ``"unreached"``.
    status: str
    symbol: str | None = None
    path: tuple[CallPathStep, ...] = ()

    @property
    def reaches(self) -> bool:
        return self.status != "unreached"


@dataclass(frozen=True, slots=True)
class TriageReport:
    """Everything known about one advisory and one project."""

    advisory_id: str
    summary: str
    severity: Severity
    aliases: tuple[str, ...]
    snapshot_id: str | None
    #: The project's components this advisory concerns.
    component: Component
    #: True when the installed version falls inside the advisory's range. False
    #: means the project is already on a safe version and the reachability
    #: answer below is hypothetical.
    version_affected: bool
    verdict: Verdict
    reach: ReachabilityResult | None
    symbols: tuple[SymbolProbe, ...]
    entry_points: tuple[EntryPointReach, ...]
    entry_point_source: EntryPointSource
    entry_point_count: int
    graph: GraphStats | None
    notes: tuple[str, ...] = ()

    @property
    def reaching_entry_points(self) -> tuple[EntryPointReach, ...]:
        return tuple(entry for entry in self.entry_points if entry.reaches)

    @property
    def is_reproducible(self) -> bool:
        return self.snapshot_id is not None


def triage(
    root: Path,
    advisory_id: str,
    source: AdvisorySource,
    *,
    options: ScanOptions | None = None,
    extra_symbols: Sequence[str] = (),
    clock: Clock | None = None,
) -> TriageReport:
    """Explain one advisory's verdict against one project.

    Args:
        root: Project directory.
        advisory_id: The advisory to explain. Any of its identifiers works, so
            a CVE and the GHSA that aliases it both resolve to the same record.
        source: Where advisories come from.
        options: Scan configuration, including the entry points and the
            environment holding the project's dependencies.
        extra_symbols: Symbols to search for in addition to the advisory's own.
            Recorded as manually supplied, because the tool cannot verify that
            the fix touched them.
        clock: Injected so a report is reproducible in tests.

    Raises:
        TriageError: if no advisory with this identifier concerns any package
            in the project's inventory, or if reachability cannot run for the
            ecosystem involved.
    """
    resolved = options or ScanOptions()
    sbom = build_inventory(root, resolved, clock or SystemClock())

    wanted = advisory_id.strip().upper()
    advisory, component = _locate(sbom.components, wanted, source)

    matched = finding_for(component, advisory)
    version_affected = matched is not None
    finding = matched if matched is not None else probe_finding(component, advisory)

    symbols = list(advisory.symbols_for(component.ecosystem, component.name))
    symbols.extend(_manual(advisory, component, extra_symbols))

    setup = prepare_reachability(root, sbom, resolved)
    if setup is None:
        raise TriageError(
            f"reachability analysis does not cover {component.ecosystem}, so there "
            f"is nothing to explain for {advisory.id}"
        )

    result = decide(finding, symbols, setup.context)
    notes = list(setup.notes)
    if not version_affected:
        notes.append(
            f"{component.name} {component.version} is outside this advisory's "
            f"affected range, so the project is not affected today. The "
            f"reachability answer below describes whether the code would be "
            f"reached if it were."
        )
    if extra_symbols:
        notes.append(
            f"{len(tuple(extra_symbols))} symbol(s) were supplied on the command "
            f"line rather than extracted from a fix commit, so this report's "
            f"confidence is capped accordingly."
        )

    return TriageReport(
        advisory_id=advisory.id,
        summary=advisory.summary,
        severity=advisory.severity,
        aliases=advisory.aliases,
        snapshot_id=source.snapshot_id,
        component=component,
        version_affected=version_affected,
        verdict=_verdict_for(result, finding),
        reach=result,
        symbols=_probe(symbols, setup),
        entry_points=_per_entry_point(setup, symbols),
        entry_point_source=setup.entry_points.source,
        entry_point_count=setup.entry_points.count,
        graph=setup.stats,
        notes=tuple(dict.fromkeys(notes)),
    )


def _locate(
    components: Sequence[Component], wanted: str, source: AdvisorySource
) -> tuple[Advisory, Component]:
    """Find the advisory and the component of this project it concerns.

    Looked up through the same ``advisories_for`` the scan uses rather than a
    by-identifier endpoint, so triage reads exactly the corpus the scan read.
    """
    with_versions = [component for component in components if component.version]
    candidates = source.advisories_for([component.purl for component in with_versions])

    for component in with_versions:
        for advisory in candidates.get(component.purl, ()):
            if wanted in {identifier.upper() for identifier in advisory.all_ids}:
                return advisory, component

    raise TriageError(
        f"no advisory matching {wanted} concerns any package in this project's "
        f"inventory of {len(with_versions)} component(s). Check the identifier, "
        f"or confirm the advisory's package is actually a dependency here."
    )


def _manual(
    advisory: Advisory, component: Component, extra: Sequence[str]
) -> list[VulnerableSymbol]:
    """Wrap operator-supplied symbols with honest provenance."""
    return [
        VulnerableSymbol(
            advisory_id=advisory.id,
            ecosystem=component.ecosystem,
            package_name=component.name,
            symbol=symbol.strip(),
            # The kind is unknown, and guessing it would change how the search
            # expands the target. Treated as a function, which expands to
            # nothing extra and so claims the least.
            kind=SymbolKind.FUNCTION,
            source=SymbolSource.MANUAL,
            confidence=Confidence.LOW,
        )
        for symbol in extra
        if symbol.strip()
    ]


def _verdict_for(result: ReachabilityResult, finding: Finding) -> Verdict:
    """Map a reachability result to the verdict a scan would record.

    Deliberately the same mapping as ``reach.verdict.apply``, so triage never
    reports an outcome a scan would not.
    """
    if result.status is ReachStatus.UNREACHABLE:
        return Verdict.NOT_AFFECTED
    if result.status.is_reachable:
        return Verdict.AFFECTED
    return Verdict.UNDER_INVESTIGATION


def _probe(
    symbols: Sequence[VulnerableSymbol], setup: ReachabilitySetup
) -> tuple[SymbolProbe, ...]:
    """Record what happened to each searched symbol.

    The distinction that matters is between a symbol that is defined in a
    linked graph, one that is only ever referenced by a call into code the
    analysis could not see, and one that appears nowhere at all.
    """
    graph = setup.graph
    search_result = setup.context.result
    probes: list[SymbolProbe] = []
    for symbol in symbols:
        defined = symbol.symbol in graph.nodes
        probes.append(
            SymbolProbe(
                symbol=symbol.symbol,
                kind=symbol.kind,
                source=symbol.source,
                confidence=symbol.confidence,
                defined=defined,
                referenced=symbol.symbol in setup.context.mentioned,
                status=search_result.status_of(symbol.symbol) if defined else "unreached",
            )
        )
    # Deduplicated on the symbol name, keeping the first, because curated and
    # extracted entries for one name would otherwise print twice.
    seen: dict[str, SymbolProbe] = {}
    for probe in probes:
        seen.setdefault(probe.symbol, probe)
    return tuple(seen.values())


def _per_entry_point(
    setup: ReachabilitySetup, symbols: Sequence[VulnerableSymbol]
) -> tuple[EntryPointReach, ...]:
    """Work out which individual entry points reach the vulnerable code.

    One search per entry point, which is what makes the answer actionable: an
    advisory reachable only from a maintenance script is a different problem
    from one reachable from a request handler. Capped, because the
    public-function fallback can produce hundreds of starting points and the
    whole point of this command is to be read.
    """
    targets = _targets_in_graph(setup, symbols)
    if not targets:
        return ()

    reaches: list[EntryPointReach] = []
    starts = setup.context.result.entry_points
    for entry_point in starts[:MAX_ENTRY_POINTS_EXPLAINED]:
        single = search(setup.graph, [entry_point])
        hit = next((target for target in targets if target in single.certain), None)
        status = "certain"
        if hit is None:
            hit = next((target for target in targets if target in single.possible), None)
            status = "possible" if hit is not None else "unreached"

        path = (
            tuple(
                CallPathStep(
                    symbol=step.symbol, file=step.file, line=step.line, edge_kind=step.edge_kind
                )
                for step in single.path_to(hit, setup.graph)
            )
            if hit is not None
            else ()
        )
        reaches.append(
            EntryPointReach(entry_point=entry_point, status=status, symbol=hit, path=path)
        )

    # Reaching entry points first: they are the reason a reader opened this.
    reaches.sort(key=lambda entry: (entry.status == "unreached", entry.entry_point))
    return tuple(reaches)


def _targets_in_graph(
    setup: ReachabilitySetup, symbols: Sequence[VulnerableSymbol]
) -> tuple[str, ...]:
    """The searched symbols that exist in the graph, expanded as the search does."""
    expanded = list(expand_targets(setup.graph, (symbol.symbol for symbol in symbols)))
    return tuple(dict.fromkeys(expanded))


__all__ = [
    "MAX_ENTRY_POINTS_EXPLAINED",
    "EntryPointReach",
    "SymbolProbe",
    "TriageError",
    "TriageReport",
    "triage",
]
