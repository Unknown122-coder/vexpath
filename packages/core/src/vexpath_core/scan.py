"""Orchestrate one scan.

This is the function the command-line tool, the GitHub Action and the hosted
worker all call. Keeping the sequence here rather than in any one of them is
what makes a verdict independent of where it was computed (ADR-0010).

The stages, in order:

1. **Inventory.** Read a lockfile or an SBOM into components with exact
   versions.
2. **Match.** Resolve each component against the advisory corpus.
3. **Reach.** Build a call graph of the project and of every dependency whose
   source is available, search from the project's entry points, and decide
   whether each finding's vulnerable code can run.

Stage three is skippable, and when it is skipped the results say so rather than
leaving a reader to assume findings were checked. Nothing is ever cleared
without it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vexpath_core import RESULTS_SCHEMA
from vexpath_core import __version__ as core_version
from vexpath_core.enums import ComponentScope, ScanMode, supports_reachability
from vexpath_core.models.advisory import Advisory
from vexpath_core.models.finding import Finding, GraphStats
from vexpath_core.models.results import ArtifactPaths, ProjectRef, SbomRef, ScanResults
from vexpath_core.models.sbom import Sbom
from vexpath_core.protocols import AdvisorySource, Clock, SystemClock
from vexpath_core.reach import (
    ReachabilityContext,
    SourceRoot,
    apply,
    build,
    choose,
    link,
    mentioned_symbols,
    search,
)
from vexpath_core.reach.cache import GraphCache, default_cache_directory
from vexpath_core.reach.dependencies import (
    DependencyGraphs,
    graphs_for,
    site_packages_directories,
)
from vexpath_core.sbom import generate_sbom, load, minimum_elements
from vexpath_core.sbom.lockfiles import find_lockfiles
from vexpath_core.vulnmatch import match

#: Directories that are not the project's own source, even when they sit at
#: its root. Vendored copies belong to their own package, and analysing them
#: as first-party would make the project look like it defines them.
NON_PROJECT_DIRECTORIES = frozenset({"vendor", "vendored", "third_party", "_vendor"})


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """How to run a scan."""

    #: Use this SBOM instead of generating one from the project's lockfile.
    sbom_path: Path | None = None
    #: Use this lockfile instead of searching for one.
    lockfile: Path | None = None
    #: Which dependency scopes to analyse. Development dependencies are
    #: included by default: they are reported, and policy decides what to do
    #: about them, because a compromised build-time dependency is still a
    #: compromise.
    include_scopes: frozenset[ComponentScope] = field(
        default_factory=lambda: frozenset(ComponentScope)
    )
    mode: ScanMode = ScanMode.CLI
    project_slug: str | None = None
    git_ref: str | None = None
    git_sha: str | None = None
    #: Run reachability analysis. Turning it off reports matching only, and
    #: nothing is ever cleared.
    reachability: bool = True
    #: Entry points to start the reachability search from. Nothing beats
    #: being told how the application starts.
    entry_points: tuple[str, ...] = ()
    #: Extra source roots for the project's own code, when the layout is not
    #: one the conventional detection finds.
    source_roots: tuple[Path, ...] = ()
    #: Where to look for installed dependencies. Defaults to the environment
    #: the scan is running in.
    environment: Path | None = None
    #: Where to cache dependency graphs. None uses the platform default.
    cache_dir: Path | None = None
    #: Skip the cache entirely, for measuring a cold build.
    use_cache: bool = True


def scan(
    root: Path,
    source: AdvisorySource,
    *,
    options: ScanOptions | None = None,
    clock: Clock | None = None,
) -> ScanResults:
    """Inventory a project, match it against advisories, and decide reachability.

    Args:
        root: Project directory.
        source: Where advisories come from. A snapshot source makes the result
            reproducible; a live source does not, and the results record which.
        options: Scan configuration.
        clock: Injected so a result is reproducible in tests.
    """
    resolved_options = options or ScanOptions()
    resolved_clock = clock or SystemClock()

    sbom = _inventory(root, resolved_options, resolved_clock)
    report = match(sbom, source, include_scopes=resolved_options.include_scopes)

    findings = report.findings
    entry_points = None
    graph_stats: GraphStats | None = None
    unsupported = list(report.unsupported_reachability_ecosystems)

    analysis_notes: list[str] = []
    if resolved_options.reachability:
        findings, entry_points, graph_stats, analysis_notes = _decide_reachability(
            root, sbom, report.findings, report.advisories, resolved_options
        )
    else:
        analysis_notes.append("Reachability analysis was not run, so no finding was cleared.")

    return ScanResults(
        schema_version=RESULTS_SCHEMA,
        core_version=core_version,
        generated_at=resolved_clock.now(),
        mode=resolved_options.mode,
        project=ProjectRef(
            slug=resolved_options.project_slug,
            git_ref=resolved_options.git_ref,
            git_sha=resolved_options.git_sha,
        ),
        sbom=SbomRef(
            format=sbom.format,
            sha256=sbom.document_sha256,
            component_count=sbom.component_count,
        ),
        advisory_snapshot_id=report.advisory_snapshot_id,
        entry_points=entry_points,
        graph=graph_stats,
        findings=findings,
        artifacts=ArtifactPaths(),
        unsupported_reachability_ecosystems=tuple(dict.fromkeys(unsupported)),
        analysis_notes=tuple(dict.fromkeys(analysis_notes)),
    )


def _decide_reachability(
    root: Path,
    sbom: Sbom,
    findings: tuple[Finding, ...],
    advisories: dict[str, Advisory],
    options: ScanOptions,
) -> tuple[tuple[Finding, ...], object, GraphStats | None, list[str]]:
    """Run the reachability stage over a matched finding set."""
    if not any(supports_reachability(component.ecosystem) for component in sbom.components):
        # Nothing here can be analysed, so building a graph would be work for
        # no verdict.
        return findings, None, None, []

    first_party = build([SourceRoot(path=path) for path in _project_roots(root, options)])

    cache = (
        GraphCache(options.cache_dir or default_cache_directory()) if options.use_cache else None
    )
    # An environment root is not itself a package directory: its installed
    # packages live under lib/python*/site-packages or Lib/site-packages
    # depending on the platform, and that has to be resolved before anything
    # can be read.
    locations = (
        None if options.environment is None else site_packages_directories(options.environment)
    )
    dependencies: DependencyGraphs = graphs_for(sbom.components, locations=locations, cache=cache)

    graph = link([first_party, *dependencies.graphs])
    entry_symbols, entry_points = choose(graph, configured=options.entry_points, root=root)
    result = search(graph, entry_symbols)
    context = ReachabilityContext(
        graph=graph,
        result=result,
        entry_points=entry_points,
        analysed_packages=frozenset(dependencies.analysed),
        mentioned=mentioned_symbols(graph),
    )

    decided: list[Finding] = []
    for finding in findings:
        advisory = advisories.get(finding.id)
        symbols = (
            advisory.symbols_for(finding.component.ecosystem, finding.component.name)
            if advisory
            else ()
        )
        if advisory is not None and advisory.is_malicious_package:
            # Installing malware runs it. Reachability is the wrong question,
            # and the finding stays as matching left it.
            decided.append(finding)
            continue
        decided.append(apply(finding, symbols, context))

    stats = GraphStats(
        first_party_nodes=sum(1 for node in graph.nodes.values() if node.is_first_party),
        first_party_edges=graph.edge_count,
        linked_packages=len(dependencies.analysed),
        unresolved_call_ratio=round(graph.quality.unresolved_ratio, 4),
        parse_error_files=graph.quality.files_failed,
        parse_error_ratio=round(graph.quality.parse_error_ratio, 4),
    )

    notes: list[str] = []
    if dependencies.unavailable:
        # Named explicitly, because a finding against one of these can be
        # confirmed but never cleared, and a reader should know which.
        shown = sorted(dependencies.unavailable)[:5]
        notes.append(
            f"{len(dependencies.unavailable)} package(s) had no source to analyse "
            f"({', '.join(shown)}), so their findings cannot be cleared"
        )

    return tuple(decided), entry_points, stats, notes


def _project_roots(root: Path, options: ScanOptions) -> list[Path]:
    """Decide which directories hold the project's own code.

    A ``src`` directory is the conventional answer when present. Otherwise the
    project root itself, which brings in more than it should but is the safe
    direction: a missed source file means missed entry points, and missed
    entry points produce clearances that were never earned.
    """
    if options.source_roots:
        return [path for path in options.source_roots if path.is_dir()]

    # A src directory is the conventional answer, and a monorepo keeps one per
    # member. Finding them means the first-party graph holds the project's own
    # code rather than every file in the repository, which keeps the inferred
    # entry-point set meaningful.
    nested = sorted(
        path
        for pattern in ("src", "*/src", "*/*/src")
        for path in root.glob(pattern)
        if path.is_dir()
        and any(path.iterdir())
        and not any(part in NON_PROJECT_DIRECTORIES for part in path.parts)
    )
    if nested:
        return nested
    return [root]


def _inventory(root: Path, options: ScanOptions, clock: Clock) -> Sbom:
    """Produce the inventory, from a supplied document or from a lockfile."""
    if options.sbom_path is not None:
        sbom = load(options.sbom_path, clock=clock)
    else:
        sbom = generate_sbom(root, lockfile=options.lockfile, clock=clock)
    # Gaps are attached to the inventory rather than raised: an incomplete
    # document is still analysable, and the gaps belong in the report.
    return sbom.model_copy(update={"minimum_element_gaps": minimum_elements.check(sbom)})


def scanned_lockfile(root: Path, options: ScanOptions | None = None) -> str:
    """Return the path a SARIF report should anchor findings to.

    Dependency findings have no line of source code, so they are anchored to
    the file that put the component there.
    """
    resolved = options or ScanOptions()
    if resolved.lockfile is not None:
        return _relative(resolved.lockfile, root)
    if resolved.sbom_path is not None:
        return _relative(resolved.sbom_path, root)
    candidates = find_lockfiles(root)
    return _relative(candidates[0], root) if candidates else "unknown"


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


__all__ = ["NON_PROJECT_DIRECTORIES", "ScanOptions", "scan", "scanned_lockfile"]
