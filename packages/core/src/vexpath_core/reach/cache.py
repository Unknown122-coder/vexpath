"""Serialise and cache call graphs.

A dependency's graph depends only on its package version and the builder that
made it, so it is built once and reused by every project that installs that
version. That is the whole point of the two-level design, and this is what
makes it pay: without a cache, every scan would reparse every dependency.

The cache key includes the builder version, so improving the builder
invalidates graphs without deleting anything. Old entries simply stop being
read and age out.

Serialisation is msgpack rather than JSON: a graph for a large package has tens
of thousands of edges, and the difference in size and parse time is the
difference between a warm scan feeling instant and feeling slow.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import msgpack

from vexpath_core.enums import EdgeKind, SymbolKind
from vexpath_core.reach.graph import BUILDER_VERSION, CallGraph, Edge, GraphQuality, Node

#: Bumped when the serialised shape changes, independently of the builder.
FORMAT_VERSION = 1


class CacheError(Exception):
    """Raised when a cached graph cannot be read or written."""


def to_bytes(graph: CallGraph) -> bytes:
    """Serialise a call graph.

    Node and edge fields are written as positional lists rather than maps. For
    a package with tens of thousands of edges, repeating four key names per
    edge is most of the file.
    """
    payload = {
        "format": FORMAT_VERSION,
        "package": graph.package,
        "version": graph.version,
        "builder": graph.builder_version,
        "entry_points": list(graph.entry_points),
        "nodes": [
            [
                node.symbol,
                node.kind.value,
                node.file,
                node.line,
                node.end_line,
                node.opaque,
                node.package,
            ]
            for node in graph.nodes.values()
        ],
        "edges": [
            [edge.source, edge.target, edge.kind.value, edge.line]
            for targets in graph.edges.values()
            for edge in targets
        ],
        "quality": [
            graph.quality.call_sites,
            graph.quality.unresolved_call_sites,
            graph.quality.files_parsed,
            graph.quality.files_failed,
            list(graph.quality.parse_errors),
        ],
    }
    packed: bytes = msgpack.packb(payload, use_bin_type=True)
    return packed


def from_bytes(data: bytes) -> CallGraph:
    """Deserialise a call graph.

    Raises:
        CacheError: if the payload is corrupt or written by a format this
            build does not read. A corrupt cache entry is discarded rather
            than trusted, because a wrong graph produces a wrong verdict.
    """
    try:
        payload = msgpack.unpackb(data, raw=False, strict_map_key=False)
    except Exception as exc:  # any failure at all means the entry is unusable
        msg = f"cached graph is not readable msgpack: {type(exc).__name__}: {exc}"
        raise CacheError(msg) from exc

    if not isinstance(payload, dict) or payload.get("format") != FORMAT_VERSION:
        msg = f"cached graph has format {payload.get('format') if isinstance(payload, dict) else '?'}, expected {FORMAT_VERSION}"
        raise CacheError(msg)

    try:
        nodes = {
            entry[0]: Node(
                symbol=entry[0],
                kind=SymbolKind(entry[1]),
                file=entry[2],
                line=entry[3],
                end_line=entry[4],
                opaque=bool(entry[5]),
                package=entry[6],
            )
            for entry in payload["nodes"]
        }
        edges: dict[str, list[Edge]] = {}
        for source, target, kind, line in payload["edges"]:
            edges.setdefault(source, []).append(
                Edge(source=source, target=target, kind=EdgeKind(kind), line=line)
            )
        call_sites, unresolved, parsed, failed, errors = payload["quality"]
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        msg = f"cached graph is structurally invalid: {type(exc).__name__}: {exc}"
        raise CacheError(msg) from exc

    return CallGraph(
        package=payload.get("package"),
        version=payload.get("version"),
        builder_version=payload.get("builder", BUILDER_VERSION),
        nodes=nodes,
        edges={source: tuple(items) for source, items in edges.items()},
        entry_points=tuple(payload.get("entry_points", ())),
        quality=GraphQuality(
            call_sites=call_sites,
            unresolved_call_sites=unresolved,
            files_parsed=parsed,
            files_failed=failed,
            parse_errors=tuple(errors),
        ),
    )


class GraphCache:
    """An on-disk cache of dependency call graphs.

    Keyed by package, version and builder version. A miss is ordinary; a
    corrupt entry is deleted and treated as a miss, because falling back to
    rebuilding is always safe and trusting a damaged graph is not.
    """

    __slots__ = ("hits", "misses", "root")

    def __init__(self, root: Path) -> None:
        self.root = root
        self.hits = 0
        self.misses = 0

    def path_for(self, package: str, version: str, builder: str = BUILDER_VERSION) -> Path:
        """Return the file a graph would live in.

        Sharded by the first two characters of the package name, so a cache
        holding thousands of entries does not put them all in one directory.
        """
        safe = "".join(
            character if character.isalnum() or character in "-_." else "_"
            for character in package.lower()
        )
        shard = safe[:2] or "__"
        return self.root / shard / f"{safe}@{version}@{builder}.msgpack"

    def get(self, package: str, version: str) -> CallGraph | None:
        """Return a cached graph, or None on a miss."""
        path = self.path_for(package, version)
        if not path.is_file():
            self.misses += 1
            return None
        try:
            graph = from_bytes(path.read_bytes())
        except (CacheError, OSError):
            # A damaged entry is worse than no entry. Remove it so the next
            # run does not pay to discover the same thing.
            path.unlink(missing_ok=True)
            self.misses += 1
            return None
        self.hits += 1
        return graph

    def put(self, graph: CallGraph) -> None:
        """Store a graph. Does nothing for a graph with no cache key."""
        if not graph.package or not graph.version:
            return
        path = self.path_for(graph.package, graph.version, graph.builder_version)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = to_bytes(graph)
        # Written through a temporary file in the same directory, so a scan
        # interrupted mid-write never leaves a half-graph for the next one to
        # read.
        handle, temporary = tempfile.mkstemp(dir=path.parent, suffix=".partial")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
            Path(temporary).replace(path)
        except OSError:
            Path(temporary).unlink(missing_ok=True)
            # A cache that cannot be written is a performance problem, not a
            # correctness one, so it is not raised.

    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0


def default_cache_directory() -> Path:
    """Where graphs are cached when the caller does not say.

    Follows the platform convention, and respects an explicit override so a CI
    job can point it at a restored cache directory.
    """
    override = os.environ.get("VEXPATH_CACHE_DIR")
    if override:
        return Path(override) / "callgraphs"
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "vexpath" / "callgraphs"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "vexpath" / "callgraphs"


__all__ = [
    "FORMAT_VERSION",
    "CacheError",
    "GraphCache",
    "default_cache_directory",
    "from_bytes",
    "to_bytes",
]
