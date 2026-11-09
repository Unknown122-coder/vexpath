"""Orchestrate one scan.

This is the function the command-line tool, the GitHub Action and the hosted
worker all call. Keeping the sequence here rather than in any one of them is
what makes a verdict independent of where it was computed (ADR-0010).

At this milestone the pipeline is inventory, then matching. Reachability slots
in between matching and the verdict in M2, which is why the stages are
separate functions over immutable models rather than one procedure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vexpath_core import RESULTS_SCHEMA
from vexpath_core import __version__ as core_version
from vexpath_core.enums import ComponentScope, ScanMode
from vexpath_core.models.results import ArtifactPaths, ProjectRef, SbomRef, ScanResults
from vexpath_core.models.sbom import Sbom
from vexpath_core.protocols import AdvisorySource, Clock, SystemClock
from vexpath_core.sbom import generate_sbom, load, minimum_elements
from vexpath_core.sbom.lockfiles import find_lockfiles
from vexpath_core.vulnmatch import match


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


def scan(
    root: Path,
    source: AdvisorySource,
    *,
    options: ScanOptions | None = None,
    clock: Clock | None = None,
) -> ScanResults:
    """Inventory a project, match it against advisories and build the results.

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
        findings=report.findings,
        artifacts=ArtifactPaths(),
        unsupported_reachability_ecosystems=report.unsupported_reachability_ecosystems,
    )


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


__all__ = ["ScanOptions", "scan", "scanned_lockfile"]
