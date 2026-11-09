"""Build a call graph from Python source.

Nothing here executes the code it reads. Modules are parsed with `ast`, which
builds a tree without running anything, and that is the property the whole
threat model rests on: this analyser is pointed at untrusted repositories and
untrusted package archives.

The builder is written for this project rather than taken from an existing one
(ADR-0008) because the two-level caching design needs output that is
deterministic and serialisable per package version, and because the precision
trade-offs have to be ours to tune against a benchmark.

## What it resolves, and what it admits it cannot

Resolved precisely:

- Direct calls to names and attribute chains, through the module's imports.
- Methods on a variable whose class is known, from `x = Foo()`, from a
  parameter annotation, or from `self.attr = Foo()` in any method.
- Methods on `self`, against the enclosing class.
- Overrides: calling `Base.method` also reaches `Sub.method` for every known
  subclass. Those edges are certain when the subclass is constructed somewhere
  in the analysed source, and guesses otherwise.
- Imports, as edges to the imported module, because importing runs its
  top-level code. Re-exports through a package's `__init__` are chained, so
  `from requests import Session` finds the class in `requests.sessions`.

Admitted rather than guessed:

- A method on a receiver of unknown type. Edges go to every same-named method
  in this build, marked as guesses, and the call site is counted unresolved.
- `getattr` on a computed name, `eval`, `exec` and dynamic imports. The
  enclosing function is marked opaque. When the object's class is known,
  `getattr(obj, name)` still yields guessed edges to that class's methods,
  which is both bounded and usually right.

Every unresolved call site is counted. The ratio travels with the verdict, so
an unreachable result can be weighed against how much the analysis could see.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from vexpath_core.enums import EdgeKind, SymbolKind
from vexpath_core.reach.astutil import decorator_names
from vexpath_core.reach.astutil import dotted_name as _dotted_name
from vexpath_core.reach.entrypoints import Detected, detect_in_module
from vexpath_core.reach.graph import (
    BUILDER_VERSION,
    WILDCARD_SUFFIX,
    CallGraph,
    Edge,
    GraphQuality,
    Node,
)

#: Directories never walked. Tests are excluded because a test suite calls
#: everything, which would make every package look fully reachable.
EXCLUDED_DIRECTORIES = frozenset(
    {
        "__pycache__",
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "site-packages",
        "build",
        "dist",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "tests",
        "test",
        "testing",
    }
)

#: Files never parsed, for the same reason.
EXCLUDED_FILE_PATTERNS = ("test_", "conftest.py")
EXCLUDED_FILE_SUFFIXES = ("_test.py",)

#: Per-file size limit. A source file this large is generated, and parsing it
#: would cost more than it tells us (see docs/06-threat-model.md).
MAX_FILE_BYTES = 5 * 1024 * 1024

#: Builtins and stdlib names that carry no information about reachability into
#: a dependency. Skipped entirely rather than counted unresolved, because a
#: distorted quality ratio makes every verdict harder to weigh.
_UNINTERESTING_CALLS = frozenset(
    {
        "print",
        "len",
        "range",
        "enumerate",
        "zip",
        "map",
        "filter",
        "sorted",
        "sum",
        "min",
        "max",
        "abs",
        "round",
        "int",
        "float",
        "str",
        "bytes",
        "bool",
        "list",
        "dict",
        "set",
        "tuple",
        "frozenset",
        "type",
        "isinstance",
        "issubclass",
        "hasattr",
        "setattr",
        "delattr",
        "repr",
        "format",
        "open",
        "iter",
        "next",
        "any",
        "all",
        "reversed",
        "super",
        "property",
        "staticmethod",
        "classmethod",
        "callable",
        "id",
        "hash",
        "vars",
        "dir",
        "getattr",
    }
)

#: Calls that defeat static analysis. A function containing one is opaque.
_OPAQUE_CALLS = frozenset({"eval", "exec", "compile", "__import__"})
_OPAQUE_ATTRIBUTES = frozenset({"import_module", "load_module", "exec_module"})


@dataclass(frozen=True, slots=True)
class SourceRoot:
    """A directory whose immediate children are top-level modules.

    For a project laid out with ``src/``, that is ``src``. For an installed
    package it is the directory containing the package itself.
    """

    path: Path
    #: Distribution this source belongs to. None means first-party code, which
    #: is what entry-point detection and reporting treat as "the project".
    package: str | None = None


# ---------------------------------------------------------------------------
# Parsed representation
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Definition:
    """A function, method or class found while parsing."""

    qualname: str
    kind: SymbolKind
    node: ast.AST
    line: int
    end_line: int
    #: Qualified name of the enclosing class, for methods.
    owner: str | None = None
    opaque: bool = False


@dataclass(slots=True)
class _ClassInfo:
    qualname: str
    #: Base classes as written, resolved as far as this build allows.
    bases: list[str] = field(default_factory=list)
    #: Method name to qualified name.
    methods: dict[str, str] = field(default_factory=dict)
    #: Attribute name to the class assigned to it, from ``self.x = Foo()``.
    attribute_types: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class _Module:
    name: str
    path: Path
    package: str | None
    tree: ast.Module
    is_package_init: bool
    #: Local name to fully qualified target, from import statements.
    imports: dict[str, str] = field(default_factory=dict)
    #: Modules imported, as edges from this module.
    imported_modules: list[tuple[str, int]] = field(default_factory=list)
    #: Names from ``from X import Y`` that might be submodules rather than
    #: definitions. Which one it is cannot be told from the statement alone, so
    #: the decision is deferred until the whole build is known.
    import_candidates: list[tuple[str, int]] = field(default_factory=list)
    definitions: list[_Definition] = field(default_factory=list)
    classes: dict[str, _ClassInfo] = field(default_factory=dict)
    #: Module-level names bound to a class, from ``x = Foo()``.
    global_types: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build(
    roots: Sequence[SourceRoot],
    *,
    package: str | None = None,
    version: str | None = None,
    include_tests: bool = False,
) -> CallGraph:
    """Build a call graph from the given source roots.

    Args:
        roots: Directories holding top-level modules.
        package: Distribution name, for a dependency graph.
        version: Distribution version, for cache keying.
        include_tests: Parse test files too. Off by default, because a test
            suite exercises everything and would make every package look
            fully reachable.
    """
    modules: dict[str, _Module] = {}
    failures: list[str] = []
    parsed = 0

    for root in roots:
        for path, module_name in _discover(root.path, include_tests=include_tests):
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError, ValueError) as exc:
                failures.append(f"{path}: {type(exc).__name__}: {exc}")
                continue
            parsed += 1
            modules.setdefault(
                module_name,
                _Module(
                    name=module_name,
                    path=path,
                    package=root.package,
                    tree=tree,
                    is_package_init=path.name == "__init__.py",
                ),
            )

    for module in modules.values():
        _collect(module)

    nodes, edges, call_sites, unresolved = _resolve(modules)

    # Entry points are found while the trees are already parsed, and only for
    # first-party code: a library has no entry points of its own.
    detected: list[Detected] = []
    for module in modules.values():
        if module.package is None:
            detected.extend(detect_in_module(module.tree, module.name))

    quality = GraphQuality(
        call_sites=call_sites,
        unresolved_call_sites=unresolved,
        files_parsed=parsed,
        files_failed=len(failures),
        parse_errors=tuple(failures[:20]),
    )
    return CallGraph(
        package=package,
        version=version,
        builder_version=BUILDER_VERSION,
        nodes=nodes,
        edges=edges,
        entry_points=tuple(
            dict.fromkeys(entry.symbol for entry in detected if entry.symbol in nodes)
        ),
        quality=quality,
    )


def _discover(root: Path, *, include_tests: bool) -> Iterator[tuple[Path, str]]:
    """Yield source files and their dotted module names."""
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts[:-1]) and not include_tests:
            continue
        if not include_tests and (
            path.name.startswith(EXCLUDED_FILE_PATTERNS)
            or path.name.endswith(EXCLUDED_FILE_SUFFIXES)
        ):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue

        parts = list(relative.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
            if not parts:
                continue
        else:
            parts[-1] = parts[-1].removesuffix(".py")
        yield path, ".".join(parts)


# ---------------------------------------------------------------------------
# Pass one: definitions, imports and class shapes
# ---------------------------------------------------------------------------


def _collect(module: _Module) -> None:
    """Record what a module defines and what it imports."""
    _collect_imports(module)
    _collect_definitions(module, module.tree, prefix=module.name, owner=None)
    _collect_global_types(module)


def _collect_imports(module: _Module) -> None:
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = alias.name
                local = alias.asname or target.split(".")[0]
                module.imports[local] = target if alias.asname else target.split(".")[0]
                module.imports.setdefault(target, target)
                module.imported_modules.append((target, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_relative(module, node)
            if base is None:
                continue
            if node.module or node.level:
                module.imported_modules.append((base, node.lineno))
            for alias in node.names:
                if alias.name == "*":
                    # A star import binds names this analysis cannot enumerate
                    # without the target module in hand. The module edge above
                    # still records that it was imported.
                    continue
                local = alias.asname or alias.name
                qualified = f"{base}.{alias.name}" if base else alias.name
                module.imports[local] = qualified
                # ``from X import Y`` imports a submodule when Y is one, and a
                # name otherwise. Importing a submodule runs it; importing a
                # name does not run the function it binds. Guessing wrong in
                # one direction hides findings and in the other floods the
                # report, so the choice is made in the resolution pass, where
                # the whole build is visible.
                module.import_candidates.append((qualified, node.lineno))


def _resolve_relative(module: _Module, node: ast.ImportFrom) -> str | None:
    """Turn a possibly relative import into an absolute module path."""
    if not node.level:
        return node.module
    parts = module.name.split(".")
    # Inside a package's __init__, the module name is already the package.
    base_parts = parts if module.is_package_init else parts[:-1]
    if node.level > 1:
        base_parts = base_parts[: -(node.level - 1)] if node.level - 1 <= len(base_parts) else []
    base = ".".join(base_parts)
    if node.module:
        return f"{base}.{node.module}" if base else node.module
    return base or None


def _collect_definitions(
    module: _Module, scope: ast.AST, *, prefix: str, owner: str | None
) -> None:
    for node in ast.iter_child_nodes(scope):
        if isinstance(node, ast.ClassDef):
            qualname = f"{prefix}.{node.name}"
            info = _ClassInfo(qualname=qualname)
            for base in node.bases:
                resolved = _dotted_name(base)
                if resolved:
                    info.bases.append(resolved)
            module.classes[qualname] = info
            module.definitions.append(
                _Definition(
                    qualname=qualname,
                    kind=SymbolKind.CLASS,
                    node=node,
                    line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    owner=owner,
                )
            )
            _collect_definitions(module, node, prefix=qualname, owner=qualname)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            qualname = f"{prefix}.{node.name}"
            kind = SymbolKind.METHOD if owner else SymbolKind.FUNCTION
            module.definitions.append(
                _Definition(
                    qualname=qualname,
                    kind=kind,
                    node=node,
                    line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    owner=owner,
                    opaque=_is_opaque(node),
                )
            )
            if owner is not None and owner in module.classes:
                module.classes[owner].methods[node.name] = qualname
                _collect_self_attributes(module.classes[owner], node, module)
            # Nested functions are reachable only through their parent, and
            # treating them as separate symbols adds noise without changing a
            # verdict, so their bodies are analysed as part of the parent.


def _collect_self_attributes(
    info: _ClassInfo, function: ast.FunctionDef | ast.AsyncFunctionDef, module: _Module
) -> None:
    """Record ``self.x = Foo()`` so ``self.x.bar()`` can be resolved later."""
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign):
            continue
        constructed = _constructed_class(node.value)
        if constructed is None:
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                info.attribute_types[target.attr] = module.imports.get(constructed, constructed)


def _collect_global_types(module: _Module) -> None:
    for node in ast.iter_child_nodes(module.tree):
        if not isinstance(node, ast.Assign):
            continue
        constructed = _constructed_class(node.value)
        if constructed is None:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                module.global_types[target.id] = module.imports.get(constructed, constructed)


def _constructed_class(value: ast.expr) -> str | None:
    """Return the class name in ``Foo()`` or ``pkg.Foo()``, if that is what this is."""
    if isinstance(value, ast.Call):
        name = _dotted_name(value.func)
        # A constructor call is indistinguishable from a function call without
        # knowing the target, so the caller resolves the name and discards it
        # when it turns out not to be a class.
        return name
    return None


def _is_opaque(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether a function uses dispatch this analysis cannot follow."""
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted_name(node.func)
        if name is None:
            continue
        leaf = name.split(".")[-1]
        if leaf in _OPAQUE_CALLS or leaf in _OPAQUE_ATTRIBUTES:
            return True
        if leaf == "getattr" and len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
            return True
    return False


# ---------------------------------------------------------------------------
# Pass two: resolution
# ---------------------------------------------------------------------------


class _Resolver:
    """Turns call sites into edges, using everything pass one collected."""

    def __init__(self, modules: dict[str, _Module]) -> None:
        self.modules = modules
        self.classes: dict[str, _ClassInfo] = {}
        self.definitions: dict[str, _Definition] = {}
        #: Method name to every qualified method with that name, for the
        #: last-resort guess at an unknown receiver.
        self.methods_by_name: dict[str, list[str]] = {}
        #: Classes constructed anywhere in this build. An override edge to a
        #: class that is actually instantiated is a real call, not a guess.
        self.instantiated: set[str] = set()
        #: Base class to its direct subclasses.
        self.subclasses: dict[str, list[str]] = {}

        for module in modules.values():
            for info in module.classes.values():
                self.classes[info.qualname] = info
                for name, qualname in info.methods.items():
                    self.methods_by_name.setdefault(name, []).append(qualname)
            for definition in module.definitions:
                self.definitions[definition.qualname] = definition

        self._index_hierarchy()
        self._index_instantiations()

    def _index_hierarchy(self) -> None:
        for module in self.modules.values():
            for info in module.classes.values():
                for base in info.bases:
                    resolved = self._resolve_class_name(module, base)
                    if resolved:
                        self.subclasses.setdefault(resolved, []).append(info.qualname)

    def _index_instantiations(self) -> None:
        for module in self.modules.values():
            for node in ast.walk(module.tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _dotted_name(node.func)
                if name is None:
                    continue
                resolved = self._resolve_class_name(module, name)
                if resolved:
                    self.instantiated.add(resolved)

    def _resolve_class_name(self, module: _Module, name: str) -> str | None:
        """Resolve a written name to a class defined in this build."""
        candidates = (
            f"{module.name}.{name}",
            module.imports.get(name, ""),
            name,
        )
        for candidate in candidates:
            if candidate and candidate in self.classes:
                return candidate
        return None

    # -- resolution of one call -------------------------------------------

    def resolve_call(
        self, module: _Module, call: ast.Call, scope: dict[str, str], owner: str | None
    ) -> list[tuple[str, EdgeKind]]:
        """Return the symbols a call may reach, with how certain each is."""
        func = call.func

        if isinstance(func, ast.Name) and func.id in _UNINTERESTING_CALLS and func.id not in scope:
            return [("", EdgeKind.STATIC)]

        if isinstance(func, ast.Name):
            target = self._resolve_plain_name(module, func.id, scope)
            return [(target, EdgeKind.STATIC)] if target else []

        if isinstance(func, ast.Attribute):
            return self._resolve_attribute(module, func, scope, owner)

        return []

    def _resolve_plain_name(self, module: _Module, name: str, scope: dict[str, str]) -> str | None:
        if name in scope:
            return scope[name]
        local = f"{module.name}.{name}"
        if local in self.definitions:
            return local
        if name in module.imports:
            return module.imports[name]
        return None

    def _resolve_attribute(
        self,
        module: _Module,
        attribute: ast.Attribute,
        scope: dict[str, str],
        owner: str | None,
    ) -> list[tuple[str, EdgeKind]]:
        receiver = attribute.value
        method = attribute.attr

        # self.method(...) and self.attr.method(...)
        if isinstance(receiver, ast.Name) and receiver.id == "self" and owner:
            info = self.classes.get(owner)
            if info and method in info.methods:
                return self._with_overrides(info.methods[method], method)
            return []
        if (
            isinstance(receiver, ast.Attribute)
            and isinstance(receiver.value, ast.Name)
            and receiver.value.id == "self"
            and owner
        ):
            info = self.classes.get(owner)
            attribute_class = info.attribute_types.get(receiver.attr) if info else None
            if attribute_class:
                return self._method_on_class(module, attribute_class, method)

        base_name = _dotted_name(receiver)
        if base_name is None:
            return self._guess_by_method_name(method)

        # A variable whose class is known, from an assignment, an annotation,
        # or a module-level binding.
        known_class = scope.get(base_name) or module.global_types.get(base_name)
        if known_class:
            resolved = self._method_on_class(module, known_class, method)
            if resolved:
                return resolved

        # A module or package path.
        if base_name in module.imports:
            return [(f"{module.imports[base_name]}.{method}", EdgeKind.STATIC)]
        local_module = f"{module.name}.{base_name}"
        if local_module in self.definitions or local_module in self.classes:
            return self._method_on_class(module, local_module, method) or [
                (f"{local_module}.{method}", EdgeKind.STATIC)
            ]

        return self._guess_by_method_name(method)

    def _method_on_class(
        self, module: _Module, class_name: str, method: str
    ) -> list[tuple[str, EdgeKind]]:
        resolved = self._resolve_class_name(module, class_name) or class_name
        info = self.classes.get(resolved)
        if info is None:
            # The class belongs to a package whose graph is not in this build.
            # Name the method anyway: linking resolves it if that graph is
            # present, and counts it as dangling if not.
            return [(f"{resolved}.{method}", EdgeKind.STATIC)]
        if method in info.methods:
            return self._with_overrides(info.methods[method], method)
        # Inherited from a base class in this build.
        for base in info.bases:
            base_resolved = self._resolve_class_name(module, base)
            base_info = self.classes.get(base_resolved) if base_resolved else None
            if base_info and method in base_info.methods:
                return self._with_overrides(base_info.methods[method], method)
        return [(f"{resolved}.{method}", EdgeKind.STATIC)]

    def _with_overrides(self, qualname: str, method: str) -> list[tuple[str, EdgeKind]]:
        """Add the subclass overrides a call to this method may actually hit.

        An override on a subclass that this code constructs is a real call, so
        the edge is certain. An override on a subclass nothing constructs here
        is a possibility, so the edge is a guess.
        """
        results: list[tuple[str, EdgeKind]] = [(qualname, EdgeKind.STATIC)]
        owner = qualname.rsplit(".", 1)[0]
        for subclass in self._descendants(owner):
            info = self.classes.get(subclass)
            if info is None or method not in info.methods:
                continue
            kind = EdgeKind.STATIC if subclass in self.instantiated else EdgeKind.DYNAMIC
            results.append((info.methods[method], kind))
        return results

    def _descendants(self, class_name: str) -> list[str]:
        found: list[str] = []
        queue = list(self.subclasses.get(class_name, ()))
        seen: set[str] = set()
        while queue:
            current = queue.pop()
            if current in seen:
                continue
            seen.add(current)
            found.append(current)
            queue.extend(self.subclasses.get(current, ()))
        return found

    def _guess_by_method_name(self, method: str) -> list[tuple[str, EdgeKind]]:
        """Last resort: the receiver's type is unknown.

        Every same-named method in this build becomes a guessed edge. That
        over-approximates, which is the safe direction, and the call site is
        counted as unresolved so the imprecision is visible in the result.
        """
        candidates = self.methods_by_name.get(method, [])
        if not candidates or len(candidates) > 12:
            # Beyond a dozen, the guess carries no information and would
            # connect half the graph to the other half.
            return []
        return [(candidate, EdgeKind.DYNAMIC) for candidate in candidates]


def _resolve(
    modules: dict[str, _Module],
) -> tuple[dict[str, Node], dict[str, tuple[Edge, ...]], int, int]:
    """Second pass: build nodes and edges from the collected definitions."""
    resolver = _Resolver(modules)
    nodes: dict[str, Node] = {}
    edges: dict[str, list[Edge]] = {}
    call_sites = 0
    unresolved = 0

    def add_edge(source: str, target: str, kind: EdgeKind, line: int | None) -> None:
        bucket = edges.setdefault(source, [])
        if not any(edge.target == target and edge.kind is kind for edge in bucket):
            bucket.append(Edge(source=source, target=target, kind=kind, line=line))

    for module in modules.values():
        relative_file = str(module.path)
        nodes[module.name] = Node(
            symbol=module.name,
            kind=SymbolKind.MODULE,
            file=relative_file,
            line=1,
            package=module.package,
        )
        # Importing a module runs its top-level code, so an import is an edge.
        for imported, line in module.imported_modules:
            add_edge(module.name, imported, EdgeKind.IMPORT, line)
        # A candidate becomes an edge only when this build confirms it is a
        # module. For a package outside this build, its own graph records which
        # of its names are modules, so the question is answered there instead
        # of guessed here.
        for candidate, line in module.import_candidates:
            if candidate in modules:
                add_edge(module.name, candidate, EdgeKind.IMPORT, line)

        # A package's __init__ re-exports names; chaining those is what makes
        # "from requests import Session" find the class in requests.sessions.
        if module.is_package_init:
            for local, target in module.imports.items():
                if "." not in target:
                    continue
                alias = f"{module.name}.{local}"
                if alias != target:
                    nodes.setdefault(
                        alias,
                        Node(
                            symbol=alias,
                            kind=SymbolKind.FUNCTION,
                            file=relative_file,
                            package=module.package,
                        ),
                    )
                    add_edge(alias, target, EdgeKind.IMPORT, None)

        for definition in module.definitions:
            nodes[definition.qualname] = Node(
                symbol=definition.qualname,
                kind=definition.kind,
                file=relative_file,
                line=definition.line,
                end_line=definition.end_line,
                opaque=definition.opaque,
                package=module.package,
            )
            # What importing a module actually runs: the module's own top-level
            # statements, and each class body. It does NOT run the functions it
            # defines, and treating definition as execution would make every
            # function of every imported package look reachable, which is the
            # single easiest way to make this analysis worthless.
            if definition.kind is SymbolKind.CLASS and definition.owner is None:
                add_edge(module.name, definition.qualname, EdgeKind.IMPORT, definition.line)

            # Decorators do run at definition time, so they are real calls.
            owner_symbol = definition.owner or module.name
            for decorator in _decorator_targets(module, definition, resolver):
                add_edge(owner_symbol, decorator, EdgeKind.STATIC, definition.line)

        for definition in module.definitions:
            if definition.kind is SymbolKind.CLASS:
                continue
            scope = _function_scope(module, definition)
            for call in _calls_in(definition.node):
                call_sites += 1
                resolved = resolver.resolve_call(module, call, scope, definition.owner)
                if resolved == [("", EdgeKind.STATIC)]:
                    # A builtin. Resolved, but not an edge worth keeping.
                    call_sites -= 1
                    continue
                if not resolved:
                    unresolved += 1
                    continue
                if all(kind is EdgeKind.DYNAMIC for _, kind in resolved):
                    unresolved += 1
                for target, kind in resolved:
                    edge_kind = (
                        EdgeKind.OPAQUE if definition.opaque and kind is EdgeKind.DYNAMIC else kind
                    )
                    add_edge(definition.qualname, target, edge_kind, call.lineno)
                    # Constructing a class runs its initialiser, which is a
                    # real call even though the source names only the class.
                    initialiser = f"{target}.__init__"
                    if initialiser in resolver.definitions:
                        add_edge(definition.qualname, initialiser, edge_kind, call.lineno)

            # An opaque function is assumed to reach what its module imports.
            if definition.opaque:
                for imported, line in module.imported_modules:
                    add_edge(definition.qualname, imported, EdgeKind.OPAQUE, line)
                for target, kind in _getattr_targets(module, definition, resolver):
                    add_edge(definition.qualname, target, kind, definition.line)

        # Module-level calls, which run on import.
        module_scope = dict(module.global_types)
        for call in _module_level_calls(module.tree):
            call_sites += 1
            resolved = resolver.resolve_call(module, call, module_scope, None)
            if resolved == [("", EdgeKind.STATIC)]:
                call_sites -= 1
                continue
            if not resolved:
                unresolved += 1
                continue
            for target, kind in resolved:
                add_edge(module.name, target, kind, call.lineno)
                initialiser = f"{target}.__init__"
                if initialiser in resolver.definitions:
                    add_edge(module.name, initialiser, kind, call.lineno)

    return (
        nodes,
        {source: tuple(bucket) for source, bucket in edges.items()},
        call_sites,
        unresolved,
    )


def _decorator_targets(module: _Module, definition: _Definition, resolver: _Resolver) -> list[str]:
    """Resolve the decorators applied to a definition.

    A decorator is called when the module is imported, so it is a genuine
    execution path, unlike the function it wraps.
    """
    node = definition.node
    if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return []
    targets: list[str] = []
    for name in decorator_names(node):
        resolved = resolver._resolve_plain_name(module, name.split(".")[0], {})
        if "." in name:
            base, _, attribute = name.rpartition(".")
            if base in module.imports:
                targets.append(f"{module.imports[base]}.{attribute}")
                continue
        if resolved:
            targets.append(resolved)
        elif name in module.imports:
            targets.append(module.imports[name])
    return targets


def _function_scope(module: _Module, definition: _Definition) -> dict[str, str]:
    """Infer the class of each local name in a function.

    Three sources, cheap and high value: parameter annotations, local
    assignments from a constructor call, and the module's own bindings.
    """
    scope: dict[str, str] = dict(module.global_types)
    node = definition.node
    if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return scope

    for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
        if argument.annotation is None:
            continue
        annotation = _dotted_name(argument.annotation)
        if annotation:
            scope[argument.arg] = module.imports.get(annotation, annotation)

    for statement in ast.walk(node):
        if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            annotation = _dotted_name(statement.annotation)
            if annotation:
                scope[statement.target.id] = module.imports.get(annotation, annotation)
        elif isinstance(statement, ast.Assign):
            constructed = _constructed_class(statement.value)
            if constructed is None:
                continue
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    scope[target.id] = module.imports.get(constructed, constructed)
    return scope


def _calls_in(node: ast.AST) -> Iterator[ast.Call]:
    """Yield every call inside a definition, including nested functions."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            yield child


def _module_level_calls(tree: ast.Module) -> Iterator[ast.Call]:
    """Yield calls that run when the module is imported.

    Function and class bodies are excluded: those run when called, and are
    attributed to their own symbol.
    """
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        for child in ast.walk(statement):
            if isinstance(child, ast.Call):
                yield child


def _getattr_targets(
    module: _Module, definition: _Definition, resolver: _Resolver
) -> list[tuple[str, EdgeKind]]:
    """Guess what ``getattr(obj, name)`` could dispatch to.

    When the object's class is known this is precise and bounded: the call can
    only reach a method of that class. It is still a guess about which one, so
    the edges are marked as such.
    """
    scope = _function_scope(module, definition)
    results: list[tuple[str, EdgeKind]] = []
    for call in _calls_in(definition.node):
        name = _dotted_name(call.func)
        if name is None or name.split(".")[-1] != "getattr" or len(call.args) < 2:
            continue
        if isinstance(call.args[1], ast.Constant):
            continue
        receiver = _dotted_name(call.args[0])
        if receiver is None:
            continue
        class_name = scope.get(receiver)
        if class_name is None:
            continue
        resolved = resolver._resolve_class_name(module, class_name)
        info = resolver.classes.get(resolved) if resolved else None
        if info is not None:
            results.extend((qualname, EdgeKind.DYNAMIC) for qualname in info.methods.values())
            continue
        # The class belongs to a package this build cannot see. The dispatch is
        # still bounded to that one class, so record it as a wildcard and let
        # linking expand it once the owning package's graph is present.
        results.append((f"{class_name}{WILDCARD_SUFFIX}", EdgeKind.DYNAMIC))
    return results


def detect_entry_points(
    roots: Sequence[SourceRoot], *, include_tests: bool = False
) -> list[Detected]:
    """Return the entry points declared in first-party source, with provenance.

    Separate from :func:`build` because the caller needs the provenance to
    decide how much to trust a verdict, and a graph carries only the symbols.
    """
    detected: list[Detected] = []
    for root in roots:
        if root.package is not None:
            continue
        for path, module_name in _discover(root.path, include_tests=include_tests):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
                continue
            detected.extend(detect_in_module(tree, module_name))
    return detected


__all__ = [
    "EXCLUDED_DIRECTORIES",
    "MAX_FILE_BYTES",
    "SourceRoot",
    "build",
    "detect_entry_points",
]
