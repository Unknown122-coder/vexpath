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

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from vexpath_core import RESULTS_SCHEMA
from vexpath_core import __version__ as core_version
from vexpath_core.enums import ComponentScope, ScanMode, supports_reachability
from vexpath_core.models.advisory import Advisory, VulnerableSymbol
from vexpath_core.models.finding import EntryPointInfo, Finding, GraphStats
from vexpath_core.models.results import ArtifactPaths, ProjectRef, SbomRef, ScanResults
from vexpath_core.models.sbom import Sbom
from vexpath_core.policy import evaluate as evaluate_policy
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
from vexpath_core.reach.archives import ArchiveSource
from vexpath_core.reach.cache import GraphCache, default_cache_directory
from vexpath_core.reach.dependencies import (
    DependencyGraphs,
    graphs_for,
    site_packages_directories,
)
from vexpath_core.reach.graph import CallGraph
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
    #: Download a dependency's source from the package index when it is not
    #: installed. Reaches the network, so it is opt-in; without it a scan of a
    #: lockfile alone can confirm findings but never clear them.
    download_missing: bool = False
    #: The gate. A preset name or a CEL expression; None evaluates nothing, so
    #: a scan that was only asked to report does not quietly acquire an
    #: opinion about whether the build should pass.
    policy: str | None = None


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

    sbom = build_inventory(root, resolved_options, resolved_clock)
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

    results = ScanResults(
        schema_version=RESULTS_SCHEMA,
        core_version=core_version,
        generated_at=resolved_clock.now(),
        mode=resolved_options.mode,
        project=ProjectRef(
            slug=resolved_options.project_slug,
            git_ref=resolved_options.git_ref,
            git_sha=resolved_options.git_sha,
            lockfile=scanned_lockfile(root, resolved_options),
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

    if resolved_options.policy is None:
        return results
    # Evaluated last, over the finished results, so a policy sees exactly what
    # a reader of the report sees. Errors are not caught here: a gate that
    # cannot be evaluated must not be reported as one that passed.
    return results.model_copy(update={"policy": evaluate_policy(results, resolved_options.policy)})


@dataclass(frozen=True, slots=True)
class ReachabilitySetup:
    """The assembled graph a verdict is computed against.

    Built once and shared, because ``vexpath reach`` has to reach the same
    conclusion as ``vexpath scan`` on the same project. A triage command that
    disagrees with the scan it is triaging is worse than no triage command, so
    both go through here.
    """

    context: ReachabilityContext
    dependencies: DependencyGraphs
    stats: GraphStats
    notes: tuple[str, ...] = ()

    @property
    def graph(self) -> CallGraph:
        return self.context.graph

    @property
    def entry_points(self) -> EntryPointInfo:
        return self.context.entry_points


def prepare_reachability(
    root: Path, sbom: Sbom, options: ScanOptions | None = None
) -> ReachabilitySetup | None:
    """Build the project's graph, link every available dependency, and search it.

    Returns None when nothing in the inventory belongs to an ecosystem this
    build can analyse, since building a graph would then be work for no
    verdict.
    """
    resolved = options or ScanOptions()
    if not any(supports_reachability(component.ecosystem) for component in sbom.components):
        return None

    first_party = build([SourceRoot(path=path) for path in _project_roots(root, resolved)])

    cache = (
        GraphCache(resolved.cache_dir or default_cache_directory()) if resolved.use_cache else None
    )
    # An environment root is not itself a package directory: its installed
    # packages live under lib/python*/site-packages or Lib/site-packages
    # depending on the platform, and that has to be resolved before anything
    # can be read.
    locations = (
        None if resolved.environment is None else site_packages_directories(resolved.environment)
    )
    archives = _archive_source() if resolved.download_missing else None
    try:
        dependencies: DependencyGraphs = graphs_for(
            sbom.components, locations=locations, cache=cache, archives=archives
        )
    finally:
        if archives is not None:
            archives.client.close()

    graph = link([first_party, *dependencies.graphs])
    entry_symbols, entry_points = choose(graph, configured=resolved.entry_points, root=root)
    result = search(graph, entry_symbols)
    context = ReachabilityContext(
        graph=graph,
        result=result,
        entry_points=entry_points,
        analysed_packages=frozenset(dependencies.analysed),
        mentioned=mentioned_symbols(graph),
    )

    notes: list[str] = []
    if dependencies.from_archive:
        # Named, because a verdict resting on a downloaded archive rests on a
        # different thing from one resting on the installed environment.
        notes.append(
            f"{len(dependencies.from_archive)} package(s) were graphed from archives "
            f"downloaded from the package index rather than from an installed "
            f"environment"
        )
    # Grouped by cause, and each cause named. One line listing five
    # packages and no reason sent a reader looking for a missing install
    # when the environment simply held a different version.
    notes.extend(_unavailable_notes(dependencies.unavailable))

    return ReachabilitySetup(
        context=context,
        dependencies=dependencies,
        stats=GraphStats(
            first_party_nodes=sum(1 for node in graph.nodes.values() if node.is_first_party),
            first_party_edges=graph.edge_count,
            linked_packages=len(dependencies.analysed),
            unresolved_call_ratio=round(graph.quality.unresolved_ratio, 4),
            parse_error_files=graph.quality.files_failed,
            parse_error_ratio=round(graph.quality.parse_error_ratio, 4),
        ),
        notes=tuple(notes),
    )


#: How many packages to name before summarising the rest.
NAMED_IN_A_NOTE = 5


def _unavailable_notes(unavailable: Mapping[str, str]) -> list[str]:
    """Say *why* each package could not be analysed, not merely that it was not.

    This used to be one line naming five packages and no reason, which hid the
    most common cause behind the least useful wording. Scanning a real project
    reported "16 package(s) had no source to analyse (argon2-cffi, fastapi,
    ...)" while every one of them was installed and perfectly readable: the
    environment simply held newer versions than the lockfile, so graphing them
    would have described code the project does not ship.

    "Not installed" and "installed, but a different version" need opposite
    responses -- install the dependencies, or reconcile the lockfile with the
    environment -- and a reader who cannot tell them apart will try the wrong
    one.
    """
    if not unavailable:
        return []

    grouped: dict[str, list[str]] = {}
    for package, reason in sorted(unavailable.items()):
        grouped.setdefault(_cause(reason), []).append(package)

    notes: list[str] = []
    for cause, packages in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        shown = ", ".join(packages[:NAMED_IN_A_NOTE])
        if len(packages) > NAMED_IN_A_NOTE:
            shown += f" and {len(packages) - NAMED_IN_A_NOTE} more"
        notes.append(
            f"{len(packages)} package(s) could not be analysed, so their findings "
            f"cannot be cleared -- {cause}: {shown}"
        )
    return notes


def _cause(reason: str) -> str:
    """Collapse a per-package reason into the cause it shares with others.

    The version-mismatch reason names both versions, so it is unique per
    package and would defeat grouping entirely -- which is the case this
    function exists for.
    """
    if "does not ship" in reason:
        return (
            "the environment has a different version from the one in the lockfile, "
            "so graphing it would describe code this project does not ship"
        )
    return reason


def symbols_to_search(finding: Finding, advisory: Advisory | None) -> tuple[VulnerableSymbol, ...]:
    """The vulnerable symbols to search for on behalf of one finding."""
    if advisory is None:
        return ()
    return tuple(advisory.symbols_for(finding.component.ecosystem, finding.component.name))


def _decide_reachability(
    root: Path,
    sbom: Sbom,
    findings: tuple[Finding, ...],
    advisories: dict[str, Advisory],
    options: ScanOptions,
) -> tuple[tuple[Finding, ...], EntryPointInfo | None, GraphStats | None, list[str]]:
    """Run the reachability stage over a matched finding set."""
    setup = prepare_reachability(root, sbom, options)
    if setup is None:
        return findings, None, None, []

    decided: list[Finding] = []
    for finding in findings:
        advisory = advisories.get(finding.id)
        if advisory is not None and advisory.is_malicious_package:
            # Installing malware runs it. Reachability is the wrong question,
            # and the finding stays as matching left it.
            decided.append(finding)
            continue
        decided.append(apply(finding, symbols_to_search(finding, advisory), setup.context))

    return tuple(decided), setup.entry_points, setup.stats, list(setup.notes)


def _archive_source() -> ArchiveSource:
    """An index-backed source of dependency sources.

    Built here rather than passed in so the HTTP client's lifetime is tied to
    one reachability run, and closed in the caller's finally block.
    """
    return ArchiveSource(client=httpx.Client(timeout=60.0, follow_redirects=True))


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


def build_inventory(root: Path, options: ScanOptions, clock: Clock) -> Sbom:
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


__all__ = [
    "NON_PROJECT_DIRECTORIES",
    "ReachabilitySetup",
    "ScanOptions",
    "build_inventory",
    "prepare_reachability",
    "scan",
    "scanned_lockfile",
    "symbols_to_search",
]
