"""Build call graphs for a project's installed dependencies.

Reachability needs to traverse a dependency's internals, not just see its
surface. Reaching ``requests.get`` says little; reaching
``Session.send`` four calls deeper is what makes a verdict worth anything. So
every dependency needs its own graph.

Where that source comes from, in order of preference:

1. **The cache.** A graph depends only on the package version and the builder,
   so it is built once and reused.
2. **The installed environment.** The project's own virtual environment
   already holds the exact versions its lockfile pins. Reading them is far
   cheaper than downloading anything, and the files are already on disk.
3. **Nothing.** A dependency with no available source is reported as such, and
   findings against it can be confirmed but never cleared.

Distribution metadata is read as data: `METADATA` and `top_level.txt` are text
files. Nothing is imported, and no installed package's code runs.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from vexpath_core.models.sbom import Component
from vexpath_core.purl import normalise_name
from vexpath_core.reach.cache import GraphCache
from vexpath_core.reach.graph import CallGraph
from vexpath_core.reach.pybuild import SourceRoot, build

#: Distributions never graphed. Build and test tooling is not part of the
#: application's execution, and graphing it wastes time on packages no
#: advisory verdict depends on.
SKIPPED_DISTRIBUTIONS = frozenset(
    {
        "pip",
        "setuptools",
        "wheel",
        "uv",
        "pytest",
        "ruff",
        "mypy",
        "coverage",
        "tox",
        "nox",
        "build",
        "twine",
        "virtualenv",
    }
)


@dataclass(frozen=True, slots=True)
class InstalledDistribution:
    """One distribution found in an environment, read from its metadata."""

    name: str
    version: str
    #: Directory holding the importable packages, usually ``site-packages``.
    location: Path
    #: Top-level import names this distribution provides.
    top_level: tuple[str, ...]

    @property
    def is_graphable(self) -> bool:
        return bool(self.top_level) and self.name not in SKIPPED_DISTRIBUTIONS


@dataclass(slots=True)
class DependencyGraphs:
    """The graphs found for a project's dependencies, and what was missed."""

    graphs: list[CallGraph] = field(default_factory=list)
    #: Packages whose graph is present, so a finding against them can be
    #: cleared. Anything outside this set can only ever be confirmed.
    analysed: set[str] = field(default_factory=set)
    #: Packages in the inventory with no available source, and why.
    unavailable: dict[str, str] = field(default_factory=dict)
    cache_hits: int = 0
    cache_misses: int = 0

    @property
    def cache_hit_ratio(self) -> float:
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total else 0.0


def site_packages_directories(interpreter: Path | None = None) -> list[Path]:
    """Return the directories an environment's packages are installed into.

    Defaults to the running interpreter's own paths, which for a scan run
    through ``uv run`` or an activated virtual environment is the project's
    environment.
    """
    if interpreter is None:
        return [Path(entry) for entry in sys.path if entry and Path(entry).name == "site-packages"]

    # An explicit environment root: find its site-packages without running
    # its interpreter, which would execute code from that environment.
    candidates = [
        *interpreter.glob("lib/python*/site-packages"),
        *interpreter.glob("Lib/site-packages"),
        *interpreter.glob("lib/site-packages"),
    ]
    # Deduplicated by resolved path. On a case-insensitive filesystem the
    # patterns above match the same directory more than once, and reading one
    # location twice means graphing every dependency twice.
    found: dict[Path, Path] = {}
    for path in candidates:
        if path.is_dir():
            found.setdefault(path.resolve(), path)
    return list(found.values())


def discover_installed(locations: Sequence[Path]) -> dict[str, InstalledDistribution]:
    """Read the distributions installed in the given directories.

    Keyed by normalised distribution name, so the result joins directly
    against an SBOM's components.
    """
    found: dict[str, InstalledDistribution] = {}
    for location in locations:
        if not location.is_dir():
            continue
        for info in sorted(location.glob("*.dist-info")):
            distribution = _read_dist_info(info, location)
            if distribution is not None:
                found.setdefault(distribution.name, distribution)
    return found


def _read_dist_info(info: Path, location: Path) -> InstalledDistribution | None:
    """Read one ``.dist-info`` directory."""
    name = ""
    version = ""
    metadata = info / "METADATA"
    if metadata.is_file():
        try:
            for line in metadata.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("Name: ") and not name:
                    name = line[6:].strip()
                elif line.startswith("Version: ") and not version:
                    version = line[9:].strip()
                elif not line.strip():
                    # Metadata headers end at the first blank line; the rest is
                    # the long description, which can be megabytes.
                    break
        except OSError:
            return None

    if not name or not version:
        # Fall back to the directory name, which encodes both.
        stem = info.name.removesuffix(".dist-info")
        name_part, _, version_part = stem.rpartition("-")
        name = name or name_part
        version = version or version_part
    if not name:
        return None

    return InstalledDistribution(
        name=normalise_name("PyPI", name),
        version=version,
        location=location,
        top_level=_top_level_names(info, location),
    )


def _top_level_names(info: Path, location: Path) -> tuple[str, ...]:
    """Find the import names a distribution provides.

    ``top_level.txt`` states them outright. When it is absent, which modern
    build backends often leave out, they are derived from the installed file
    list instead.
    """
    declared = info / "top_level.txt"
    if declared.is_file():
        try:
            names = [
                line.strip()
                for line in declared.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.startswith("_")
            ]
            if names:
                return tuple(dict.fromkeys(names))
        except OSError:
            pass

    record = info / "RECORD"
    if record.is_file():
        try:
            names = []
            for line in record.read_text(encoding="utf-8", errors="replace").splitlines():
                path = line.split(",", 1)[0]
                if not path or path.startswith("..") or ".dist-info/" in path:
                    continue
                head = path.split("/")[0]
                if head.endswith(".py"):
                    names.append(head.removesuffix(".py"))
                elif "/" in path and not head.endswith((".dist-info", ".data")):
                    names.append(head)
            unique = [
                name
                for name in dict.fromkeys(names)
                if (location / name).is_dir() or (location / f"{name}.py").is_file()
            ]
            if unique:
                return tuple(unique)
        except OSError:
            pass

    return ()


def graphs_for(
    components: Iterable[Component],
    *,
    locations: Sequence[Path] | None = None,
    cache: GraphCache | None = None,
) -> DependencyGraphs:
    """Build or load a call graph for each component that has one available.

    Only components whose installed version matches the inventory are graphed.
    A version mismatch means the environment is not what the lockfile
    describes, and graphing the wrong version would produce a verdict about
    code the project does not ship.
    """
    installed = discover_installed(
        locations if locations is not None else site_packages_directories()
    )
    result = DependencyGraphs()

    for component in components:
        if component.ecosystem != "PyPI":
            # Other ecosystems are reported as unsupported by the verdict
            # layer, not as missing graphs.
            continue

        distribution = installed.get(component.name)
        if distribution is None:
            result.unavailable[component.name] = "not installed in the environment being scanned"
            continue
        if distribution.version != component.version:
            result.unavailable[component.name] = (
                f"the environment has {distribution.version} but the inventory "
                f"says {component.version}, so its graph would describe code "
                f"this project does not ship"
            )
            continue
        if not distribution.is_graphable:
            result.unavailable[component.name] = (
                "no importable top-level package, or excluded as build tooling"
            )
            continue

        graph = cache.get(component.name, component.version) if cache else None
        if graph is not None:
            result.cache_hits += 1
        else:
            result.cache_misses += 1
            graph = build(
                [
                    SourceRoot(
                        path=distribution.location,
                        package=component.name,
                        top_level=distribution.top_level,
                    )
                ],
                package=component.name,
                version=component.version,
            )
            if cache is not None:
                cache.put(graph)

        if len(graph) == 0:
            result.unavailable[component.name] = (
                "its installed files yielded no parsable Python, so there is nothing to traverse"
            )
            continue

        result.graphs.append(graph)
        result.analysed.add(component.name)

    return result


__all__ = [
    "SKIPPED_DISTRIBUTIONS",
    "DependencyGraphs",
    "InstalledDistribution",
    "discover_installed",
    "graphs_for",
    "site_packages_directories",
]
