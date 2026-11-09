"""Find where execution can begin.

Reachability is meaningless without a starting point, and the choice of
starting points decides every verdict. Getting it wrong in one direction
reports vulnerabilities that cannot run; in the other it clears ones that can.
The second is the failure this project refuses to make, so detection is
deliberately generous, and when it has to guess it says so by lowering the
confidence of every result that depends on it.

Sources, best first:

1. **Configuration.** An explicit list in ``.vexpath.yml``. Nothing beats
   someone telling you how their application starts.
2. **Package metadata.** Console scripts declared in ``pyproject.toml`` or
   ``setup.cfg``, which are read as data and never executed.
3. **A main guard.** ``if __name__ == "__main__":`` and ``__main__.py``.
4. **Framework conventions.** Web routes, task handlers, management commands,
   command-line commands, serverless handlers, and the module-level
   application objects that a server imports.
5. **Fallback.** Every public function in first-party code. This
   over-approximates on purpose, and is reported as an inferred result so no
   reader mistakes it for knowledge.

Module-level code is always an entry point in its own right: importing a module
runs it, so anything the import chain touches is reachable regardless of which
function the program calls first.
"""

from __future__ import annotations

import ast
import configparser
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from vexpath_core.enums import EntryPointSource, SymbolKind
from vexpath_core.models.finding import EntryPointInfo
from vexpath_core.reach.astutil import decorator_names, is_dunder_main_guard
from vexpath_core.reach.graph import CallGraph

#: Decorator attribute names that mark a function as externally invoked. Only
#: the last component is matched, so ``app.get``, ``router.get`` and
#: ``blueprint.get`` all count without naming every framework object.
FRAMEWORK_DECORATORS = frozenset(
    {
        # HTTP routing: Flask, FastAPI, Starlette, Sanic, Bottle.
        "route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "websocket",
        "websocket_route",
        "api_view",
        "endpoint",
        # Background work: Celery, Dramatiq, RQ, APScheduler.
        "task",
        "shared_task",
        "periodic_task",
        "actor",
        "scheduled_job",
        # Command-line entry points: Click, Typer.
        "command",
        "group",
        # Django signals and application hooks.
        "receiver",
        "on_event",
        "before_request",
        "after_request",
        "errorhandler",
        # Test-adjacent frameworks deliberately absent: a test harness calls
        # everything, which would make every package look fully reachable.
    }
)

#: Function names that serverless platforms invoke by convention.
HANDLER_NAMES = frozenset({"handler", "lambda_handler", "main", "handle"})

#: Module-level names a server imports and calls. Reaching the module reaches
#: whatever building them touched.
APPLICATION_OBJECTS = frozenset({"app", "application", "asgi_application", "wsgi_application"})


@dataclass(frozen=True, slots=True)
class Detected:
    """One entry point and where it came from."""

    symbol: str
    source: EntryPointSource


def detect_in_module(tree: ast.Module, module_name: str) -> list[Detected]:
    """Find entry points declared in one module's source.

    Covers the main guard and framework conventions. Package metadata and the
    public fallback are handled elsewhere, because neither is visible in a
    single module.
    """
    found: list[Detected] = []

    for statement in tree.body:
        if is_dunder_main_guard(statement):
            # The guard's body runs when the module is executed directly, and
            # it is attributed to the module because that is what runs.
            found.append(Detected(module_name, EntryPointSource.DUNDER_MAIN))
            break

    if module_name.endswith(".__main__") or module_name == "__main__":
        found.append(Detected(module_name, EntryPointSource.DUNDER_MAIN))

    # A module-level application object means a server imports this module.
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id in APPLICATION_OBJECTS:
                    found.append(Detected(module_name, EntryPointSource.FRAMEWORK))

    found.extend(_framework_definitions(tree, module_name))
    return found


def _framework_definitions(tree: ast.Module, module_name: str) -> list[Detected]:
    found: list[Detected] = []
    is_management_command = ".management.commands." in f".{module_name}."
    is_url_conf = module_name.endswith(".urls") or module_name == "urls"

    def visit(scope: ast.AST, prefix: str, owner: str | None) -> None:
        for node in ast.iter_child_nodes(scope):
            if isinstance(node, ast.ClassDef):
                qualname = f"{prefix}.{node.name}"
                # Django management commands are invoked through handle().
                if is_management_command and node.name == "Command":
                    found.append(Detected(f"{qualname}.handle", EntryPointSource.FRAMEWORK))
                visit(node, qualname, qualname)
                continue
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            qualname = f"{prefix}.{node.name}"
            decorators = {name.split(".")[-1] for name in decorator_names(node)}
            if decorators & FRAMEWORK_DECORATORS or (owner is None and node.name in HANDLER_NAMES):
                found.append(Detected(qualname, EntryPointSource.FRAMEWORK))

    visit(tree, module_name, None)

    if is_url_conf:
        # A URL configuration names its views in data rather than decorating
        # them, so the module itself is the starting point and its imports
        # carry the search to the views.
        found.append(Detected(module_name, EntryPointSource.FRAMEWORK))
    return found


def from_package_metadata(root: Path) -> list[Detected]:
    """Read declared console scripts, without executing anything.

    ``pyproject.toml`` and ``setup.cfg`` are parsed as data. ``setup.py`` is
    never run, so a project declaring its scripts only in executable code
    contributes nothing here, and the fallback covers it.
    """
    found: list[Detected] = []

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            with pyproject.open("rb") as handle:
                data = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            data = {}
        project = data.get("project", {})
        if isinstance(project, dict):
            for table in ("scripts", "gui-scripts"):
                entries = project.get(table, {})
                if isinstance(entries, dict):
                    found.extend(
                        Detected(_normalise_target(target), EntryPointSource.PACKAGE_METADATA)
                        for target in entries.values()
                        if isinstance(target, str)
                    )
            plugins = project.get("entry-points", {})
            if isinstance(plugins, dict):
                for group in plugins.values():
                    if isinstance(group, dict):
                        found.extend(
                            Detected(_normalise_target(target), EntryPointSource.PACKAGE_METADATA)
                            for target in group.values()
                            if isinstance(target, str)
                        )
        poetry = data.get("tool", {})
        poetry_scripts = (
            poetry.get("poetry", {}).get("scripts", {}) if isinstance(poetry, dict) else {}
        )
        if isinstance(poetry_scripts, dict):
            found.extend(
                Detected(_normalise_target(target), EntryPointSource.PACKAGE_METADATA)
                for target in poetry_scripts.values()
                if isinstance(target, str)
            )

    setup_cfg = root / "setup.cfg"
    if setup_cfg.is_file():
        parser = configparser.ConfigParser()
        try:
            parser.read(setup_cfg, encoding="utf-8")
            raw = parser.get("options.entry_points", "console_scripts", fallback="")
            for line in raw.splitlines():
                _, separator, target = line.partition("=")
                if separator and target.strip():
                    found.append(
                        Detected(
                            _normalise_target(target.strip()),
                            EntryPointSource.PACKAGE_METADATA,
                        )
                    )
        except configparser.Error:
            pass

    return found


def _normalise_target(target: str) -> str:
    """Turn ``package.module:function`` into a dotted symbol."""
    module, separator, attribute = target.partition(":")
    cleaned = attribute.split("[")[0].strip()
    if separator and cleaned:
        return f"{module.strip()}.{cleaned}"
    return module.strip()


def from_config(entries: Iterable[str]) -> list[Detected]:
    """Accept explicitly configured entry points."""
    return [
        Detected(_normalise_target(entry), EntryPointSource.CONFIG)
        for entry in entries
        if entry.strip()
    ]


def public_fallback(graph: CallGraph) -> list[Detected]:
    """Every public function and module in first-party code.

    The last resort. It over-approximates, which is the safe direction, and
    the caller lowers confidence because of it.
    """
    found: list[Detected] = []
    for symbol, node in graph.nodes.items():
        if not node.is_first_party:
            continue
        if any(part.startswith("_") for part in symbol.split(".")[1:]):
            continue
        if node.kind in {SymbolKind.FUNCTION, SymbolKind.MODULE}:
            found.append(Detected(symbol, EntryPointSource.FALLBACK_PUBLIC))
    return found


def choose(
    graph: CallGraph,
    *,
    configured: Sequence[str] = (),
    root: Path | None = None,
    detected: Sequence[Detected] = (),
) -> tuple[tuple[str, ...], EntryPointInfo]:
    """Settle on the entry points for a scan, and report where they came from.

    Sources are combined rather than ranked exclusively: a project with both a
    console script and web routes starts at both. The reported source is the
    most reliable one that contributed, because that is what determines how
    much a verdict can be trusted.

    Module-level symbols of first-party code are always included. Importing a
    module runs it, so the import chain is a real execution path whatever the
    program's nominal entry point is.
    """
    candidates: list[Detected] = []
    candidates.extend(from_config(configured))
    if root is not None:
        candidates.extend(from_package_metadata(root))
    candidates.extend(detected)

    # Keep only symbols the graph actually contains, so a stale configuration
    # entry cannot silently contribute nothing while looking like a source.
    present = [entry for entry in candidates if entry.symbol in graph.nodes]

    if not present:
        present = [entry for entry in public_fallback(graph) if entry.symbol in graph.nodes]

    first_party_modules = [
        Detected(symbol, EntryPointSource.FRAMEWORK)
        for symbol, node in graph.nodes.items()
        if node.is_first_party and node.kind is SymbolKind.MODULE
    ]
    combined = {entry.symbol: entry for entry in [*first_party_modules, *present]}

    best = min(
        (entry.source for entry in present),
        key=_source_rank,
        default=EntryPointSource.FALLBACK_PUBLIC,
    )
    symbols = tuple(sorted(combined))
    return symbols, EntryPointInfo(source=best, count=len(symbols), items=symbols[:50])


_SOURCE_RANK: dict[EntryPointSource, int] = {
    EntryPointSource.CONFIG: 0,
    EntryPointSource.PACKAGE_METADATA: 1,
    EntryPointSource.DUNDER_MAIN: 2,
    EntryPointSource.FRAMEWORK: 3,
    EntryPointSource.FALLBACK_PUBLIC: 4,
}


def _source_rank(source: EntryPointSource) -> int:
    return _SOURCE_RANK[source]


def is_inferred(source: EntryPointSource) -> bool:
    """Whether this source is a guess rather than a declaration.

    An inferred set of entry points lowers the confidence of every result that
    depends on it, including unreachable ones: not having found the real
    starting point is a reason to doubt an absence of paths.
    """
    return source is EntryPointSource.FALLBACK_PUBLIC


__all__ = [
    "APPLICATION_OBJECTS",
    "FRAMEWORK_DECORATORS",
    "HANDLER_NAMES",
    "Detected",
    "choose",
    "detect_in_module",
    "from_config",
    "from_package_metadata",
    "is_inferred",
    "public_fallback",
]
