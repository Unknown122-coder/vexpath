"""Call-graph structures and reachability search.

The design is two-level, and that shapes everything here. A graph is built once
per package version and cached; graphs are *linked* at scan time by merging
them, which is a dictionary union rather than a rebuild. An edge whose target
lives in another package is recorded by its fully qualified name and simply
resolves once that package's graph is present. A target that never resolves is
a dangling edge, which the search skips and the statistics count.

Two properties of the search matter more than its speed:

**Confirmed and possible are answered separately.** The search runs twice: once
over statically resolved edges alone, and once over every edge including the
conservatively guessed ones. A symbol reached in the first pass has a path that
really exists. A symbol reached only in the second might. Collapsing the two
would either overstate certainty or bury real findings, and the product's whole
value rests on telling them apart.

**Evidence is reconstructable.** The search keeps a predecessor map, so any
reached symbol can be explained as a concrete path from a named entry point.
A verdict without that is an assertion.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field

from vexpath_core.enums import EdgeKind, SymbolKind

#: Bumped whenever the builder's output changes in a way that invalidates
#: cached graphs. Stored with every cached graph so a rebuild can be rolled out
#: gradually rather than by deleting the cache.
BUILDER_VERSION = "2"

#: Suffix marking an edge target as "any method of this class". The builder
#: emits one when it knows a dispatch is bounded to a single class but cannot
#: see that class's methods, because they live in a package it was not built
#: with. Linking expands it against the merged graph.
WILDCARD_SUFFIX = ".*"


@dataclass(frozen=True, slots=True)
class Node:
    """One definition in the graph: a function, method, class or module."""

    symbol: str
    kind: SymbolKind
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    #: True when the definition uses dynamic dispatch this analysis cannot
    #: follow: ``eval``, ``exec``, ``getattr`` on a computed name, or a dynamic
    #: import. Such a function is assumed to reach anything it can see.
    opaque: bool = False
    #: Distribution this symbol belongs to, or None for first-party code.
    package: str | None = None

    @property
    def is_first_party(self) -> bool:
        return self.package is None


@dataclass(frozen=True, slots=True)
class Edge:
    """A "may call" relationship, and how confidently it was resolved."""

    source: str
    target: str
    kind: EdgeKind = EdgeKind.STATIC
    line: int | None = None

    @property
    def is_certain(self) -> bool:
        """Whether this edge represents a call that definitely exists.

        Import edges count: importing a module runs its top-level code.
        """
        return self.kind in {EdgeKind.STATIC, EdgeKind.IMPORT}


@dataclass(frozen=True, slots=True)
class GraphQuality:
    """How much of the code the builder could actually see.

    Published with every verdict. A reader deciding whether to trust an
    unreachable result needs to know how much the analysis could not resolve,
    and hiding it would make the verdict unfalsifiable.
    """

    call_sites: int = 0
    unresolved_call_sites: int = 0
    files_parsed: int = 0
    files_failed: int = 0
    #: Files that failed to parse, for diagnosis. Capped, not exhaustive.
    parse_errors: tuple[str, ...] = ()

    @property
    def unresolved_ratio(self) -> float:
        return self.unresolved_call_sites / self.call_sites if self.call_sites else 0.0

    @property
    def parse_error_ratio(self) -> float:
        total = self.files_parsed + self.files_failed
        return self.files_failed / total if total else 0.0

    def merge(self, other: GraphQuality) -> GraphQuality:
        return GraphQuality(
            call_sites=self.call_sites + other.call_sites,
            unresolved_call_sites=self.unresolved_call_sites + other.unresolved_call_sites,
            files_parsed=self.files_parsed + other.files_parsed,
            files_failed=self.files_failed + other.files_failed,
            parse_errors=(*self.parse_errors, *other.parse_errors)[:20],
        )


@dataclass(frozen=True, slots=True)
class CallGraph:
    """A call graph for one package version, or for a project's own code."""

    #: Distribution name, or None for first-party code.
    package: str | None = None
    version: str | None = None
    builder_version: str = BUILDER_VERSION
    nodes: dict[str, Node] = field(default_factory=dict)
    #: Adjacency list. Keys are symbols; every key is also a node.
    edges: dict[str, tuple[Edge, ...]] = field(default_factory=dict)
    #: Symbols from which execution can begin. Only first-party graphs have
    #: these; a library has no entry points of its own.
    entry_points: tuple[str, ...] = ()
    quality: GraphQuality = field(default_factory=GraphQuality)

    def __len__(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(targets) for targets in self.edges.values())

    def successors(self, symbol: str) -> tuple[Edge, ...]:
        return self.edges.get(symbol, ())

    def symbols_in_package(self, package: str) -> tuple[str, ...]:
        return tuple(symbol for symbol, node in self.nodes.items() if node.package == package)


def link(graphs: Iterable[CallGraph]) -> CallGraph:
    """Merge graphs into one searchable whole.

    Linking is a union, not a rebuild, which is what makes a warm scan fast:
    a dependency's graph is built once per version and reused by every project
    that installs it.

    Where two graphs define the same symbol, the first wins. That favours
    first-party code, which callers pass first, and it is the right precedence:
    a project that shadows a dependency's module runs its own.
    """
    nodes: dict[str, Node] = {}
    edges: dict[str, list[Edge]] = {}
    entry_points: list[str] = []
    quality = GraphQuality()

    for graph in graphs:
        for symbol, node in graph.nodes.items():
            nodes.setdefault(symbol, node)
        for symbol, targets in graph.edges.items():
            edges.setdefault(symbol, []).extend(targets)
        entry_points.extend(graph.entry_points)
        quality = quality.merge(graph.quality)

    _expand_wildcards(nodes, edges)
    _resolve_aliases(nodes, edges)

    return CallGraph(
        nodes=nodes,
        edges={symbol: tuple(targets) for symbol, targets in edges.items()},
        entry_points=tuple(dict.fromkeys(entry_points)),
        quality=quality,
    )


def _expand_wildcards(nodes: dict[str, Node], edges: dict[str, list[Edge]]) -> None:
    """Replace "any method of this class" targets with the real methods.

    The builder emits a wildcard when it can bound a dynamic dispatch to one
    class but cannot see that class's methods. Once the owning package's graph
    is linked, the methods are known, so the guess becomes a bounded set of
    guessed edges rather than a dead end.
    """
    methods_by_owner: dict[str, list[str]] = {}
    for symbol, node in nodes.items():
        if node.kind is SymbolKind.METHOD:
            owner, _, _ = symbol.rpartition(".")
            methods_by_owner.setdefault(owner, []).append(symbol)

    for source, targets in list(edges.items()):
        expanded: list[Edge] = []
        for edge in targets:
            if not edge.target.endswith(WILDCARD_SUFFIX):
                expanded.append(edge)
                continue
            owner = edge.target[: -len(WILDCARD_SUFFIX)]
            for method in methods_by_owner.get(owner, ()):
                expanded.append(Edge(source=source, target=method, kind=edge.kind, line=edge.line))
        edges[source] = expanded


def _resolve_aliases(nodes: dict[str, Node], edges: dict[str, list[Edge]]) -> None:
    """Follow re-exports so a method on a re-exported class resolves.

    ``from requests import Session`` names the class ``requests.Session``, but
    the definition is ``requests.sessions.Session``, so a call to
    ``requests.Session.get`` would dangle. The package's own graph records the
    re-export as an alias edge, and this rewrites targets through it.

    Without this, every method call on a class imported from a package root
    would silently fail to match an advisory's symbols, which is the quiet
    miss this project exists to avoid.
    """
    aliases: dict[str, str] = {}
    for source, targets in edges.items():
        node = nodes.get(source)
        if node is None or node.kind is SymbolKind.MODULE:
            continue
        imports = [edge.target for edge in targets if edge.kind is EdgeKind.IMPORT]
        if len(imports) == 1 and imports[0] != source:
            aliases[source] = imports[0]

    if not aliases:
        return

    for source, targets in list(edges.items()):
        additions: list[Edge] = []
        for edge in targets:
            if edge.target in nodes:
                continue
            rewritten = _rewrite_through_aliases(edge.target, aliases, nodes)
            if rewritten is not None:
                additions.append(
                    Edge(source=source, target=rewritten, kind=edge.kind, line=edge.line)
                )
        if additions:
            edges[source] = [*targets, *additions]


def _rewrite_through_aliases(
    target: str, aliases: dict[str, str], nodes: dict[str, Node], depth: int = 0
) -> str | None:
    """Rewrite ``alias.rest`` into ``definition.rest`` if that exists."""
    if depth > 4:
        return None
    parts = target.split(".")
    for cut in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:cut])
        if prefix not in aliases:
            continue
        candidate = ".".join([aliases[prefix], *parts[cut:]])
        if candidate in nodes:
            return candidate
        deeper = _rewrite_through_aliases(candidate, aliases, nodes, depth + 1)
        if deeper is not None:
            return deeper
    return None


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PathStep:
    """One hop of an explanation."""

    symbol: str
    file: str | None
    line: int | None
    edge_kind: EdgeKind


@dataclass(frozen=True, slots=True)
class SearchResult:
    """What the search reached, and how.

    ``certain`` holds symbols with a path made only of resolved calls and
    imports. ``possible`` holds everything reachable at all, including through
    conservatively guessed edges. ``certain`` is always a subset.
    """

    certain: frozenset[str]
    possible: frozenset[str]
    entry_points: tuple[str, ...]
    _certain_from: Mapping[str, Edge] = field(default_factory=dict, repr=False)
    _possible_from: Mapping[str, Edge] = field(default_factory=dict, repr=False)

    def status_of(self, symbol: str) -> str:
        """Return ``"certain"``, ``"possible"`` or ``"unreached"``."""
        if symbol in self.certain:
            return "certain"
        return "possible" if symbol in self.possible else "unreached"

    def reached(self, symbol: str) -> bool:
        return symbol in self.possible

    def path_to(self, symbol: str, graph: CallGraph) -> tuple[PathStep, ...]:
        """Reconstruct the shortest path from an entry point to ``symbol``.

        Prefers a path of certain edges when one exists, so the evidence shown
        matches the verdict given.
        """
        for predecessors in (self._certain_from, self._possible_from):
            if symbol in predecessors or symbol in self.entry_points:
                return _walk_back(symbol, predecessors, graph)
        return ()


def _walk_back(
    symbol: str, predecessors: Mapping[str, Edge], graph: CallGraph
) -> tuple[PathStep, ...]:
    """Rebuild the path to ``symbol`` as a readable forward sequence.

    A step's ``edge_kind`` describes how execution arrived *at* that symbol, so
    a reader can see which hop was the guess. The first step is an entry point
    and has no incoming edge.
    """
    chain: list[Edge] = []
    current = symbol
    seen = {current}
    while True:
        edge = predecessors.get(current)
        if edge is None:
            break
        chain.append(edge)
        current = edge.source
        if current in seen:
            # Defensive: a predecessor map from a breadth-first search cannot
            # contain a cycle, but a corrupted cache must not hang a scan.
            break
        seen.add(current)

    chain.reverse()

    def step(name: str, kind: EdgeKind, line: int | None = None) -> PathStep:
        node = graph.nodes.get(name)
        return PathStep(
            symbol=name,
            file=node.file if node else None,
            line=line if line is not None else (node.line if node else None),
            edge_kind=kind,
        )

    if not chain:
        # The symbol is itself an entry point.
        return (step(symbol, EdgeKind.STATIC),)

    steps = [step(chain[0].source, EdgeKind.STATIC)]
    steps.extend(step(edge.target, edge.kind, edge.line) for edge in chain)
    return tuple(steps)


def search(graph: CallGraph, entry_points: Sequence[str] | None = None) -> SearchResult:
    """Find everything reachable from the entry points.

    Two breadth-first passes: one over certain edges, one over all of them.
    Running them separately is what lets a verdict distinguish a path that
    exists from a path that might.
    """
    starts = tuple(entry_points if entry_points is not None else graph.entry_points)
    present = tuple(symbol for symbol in starts if symbol in graph.nodes)

    certain, certain_from = _traverse(graph, present, certain_only=True)
    possible, possible_from = _traverse(graph, present, certain_only=False)

    return SearchResult(
        certain=frozenset(certain),
        possible=frozenset(possible),
        entry_points=present,
        _certain_from=certain_from,
        _possible_from=possible_from,
    )


def _traverse(
    graph: CallGraph, starts: Sequence[str], *, certain_only: bool
) -> tuple[set[str], dict[str, Edge]]:
    reached: set[str] = set(starts)
    predecessors: dict[str, Edge] = {}
    queue: deque[str] = deque(starts)

    while queue:
        current = queue.popleft()
        node = graph.nodes.get(current)
        for edge in graph.successors(current):
            if certain_only and not edge.is_certain:
                continue
            # An opaque function is assumed to reach what it can see, so its
            # outgoing edges are followed even in the certain pass only when
            # the edge itself is certain. The opaque marking shows up as edge
            # kind, which the filter above already handles.
            if edge.target in reached:
                continue
            reached.add(edge.target)
            predecessors[edge.target] = edge
            queue.append(edge.target)
        if node is not None and node.opaque and not certain_only:
            # Nothing extra to enqueue: the builder already emitted OPAQUE
            # edges for what an opaque function can see. This branch exists to
            # document that the marking is deliberate, not forgotten.
            pass

    return reached, predecessors


def matched_symbols(
    result: SearchResult, targets: Iterable[str], graph: CallGraph
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split target symbols into those reached certainly and those possibly.

    Target symbols come from an advisory and may name something this build of
    the package does not contain, for instance a function renamed in a later
    release. Those are reported as neither, and the caller lowers confidence
    rather than claiming the absence proves safety.
    """
    certain: list[str] = []
    possible: list[str] = []
    for target in targets:
        if target not in graph.nodes:
            continue
        if target in result.certain:
            certain.append(target)
        elif target in result.possible:
            possible.append(target)
    return tuple(certain), tuple(possible)


def expand_targets(graph: CallGraph, symbols: Iterable[str]) -> Iterator[str]:
    """Yield the graph symbols an advisory's targets actually correspond to.

    An advisory names a symbol as the upstream repository spells it, such as
    ``requests.adapters.HTTPAdapter.send``. Three cases are handled:

    - The symbol is in the graph. Use it.
    - The symbol names a module. Use the module node, because reaching an
      import is reaching module-level code.
    - The symbol names a class. Use the class and every method on it, since the
      fix touching a class means its behaviour changed.
    """
    for symbol in symbols:
        if symbol in graph.nodes:
            yield symbol
            node = graph.nodes[symbol]
            if node.kind is SymbolKind.CLASS:
                prefix = f"{symbol}."
                for candidate, candidate_node in graph.nodes.items():
                    if candidate.startswith(prefix) and candidate_node.kind in {
                        SymbolKind.METHOD,
                        SymbolKind.FUNCTION,
                    }:
                        yield candidate


__all__ = [
    "BUILDER_VERSION",
    "WILDCARD_SUFFIX",
    "CallGraph",
    "Edge",
    "GraphQuality",
    "Node",
    "PathStep",
    "SearchResult",
    "expand_targets",
    "link",
    "matched_symbols",
    "search",
]
