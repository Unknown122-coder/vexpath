"""The Python call-graph builder.

Each test writes a tiny project and checks one resolution rule. The rules
matter in both directions: missing an edge hides a real vulnerability, and
inventing one floods the report with noise that trains people to ignore it.

The most important test in this file is the one asserting that importing a
module does *not* reach the functions it defines. Getting that wrong makes
every function of every installed package look reachable, which would make the
whole analysis worthless while still appearing to work.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from vexpath_core.enums import EdgeKind, SymbolKind
from vexpath_core.reach.graph import CallGraph, link, search
from vexpath_core.reach.pybuild import MAX_FILE_BYTES, SourceRoot, build


def write(root: Path, relative: str, body: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
    return path


def graph_for(root: Path, **kwargs: object) -> CallGraph:
    return build([SourceRoot(path=root)], **kwargs)  # type: ignore[arg-type]


def targets(graph: CallGraph, source: str) -> set[str]:
    return {edge.target for edge in graph.successors(source)}


def kinds(graph: CallGraph, source: str, target: str) -> set[EdgeKind]:
    return {edge.kind for edge in graph.successors(source) if edge.target == target}


# --- The rule that makes the analysis mean anything -----------------------


def test_importing_a_module_does_not_reach_the_functions_it_defines(
    tmp_path: Path,
) -> None:
    """Defining a function is not calling it.

    If an import reached every function in the module, every function of every
    installed package would be reachable and no finding could ever be cleared.
    """
    write(
        tmp_path,
        "pkg/__init__.py",
        """
        from pkg import impl
        """,
    )
    write(
        tmp_path,
        "pkg/impl.py",
        """
        def never_called():
            return dangerous()


        def dangerous():
            return 1
        """,
    )
    graph = graph_for(tmp_path)
    result = search(graph, ["pkg"])

    assert "pkg.impl" in result.certain
    assert "pkg.impl.never_called" not in result.possible
    assert "pkg.impl.dangerous" not in result.possible


def test_importing_a_module_does_run_its_top_level_code(tmp_path: Path) -> None:
    write(
        tmp_path,
        "pkg/__init__.py",
        """
        from pkg.impl import setup

        setup()
        """,
    )
    write(
        tmp_path,
        "pkg/impl.py",
        """
        def setup():
            return risky()


        def risky():
            return 1
        """,
    )
    graph = graph_for(tmp_path)
    result = search(graph, ["pkg"])
    assert "pkg.impl.setup" in result.certain
    assert "pkg.impl.risky" in result.certain


def test_a_class_body_runs_on_import_but_its_methods_do_not(tmp_path: Path) -> None:
    write(
        tmp_path,
        "pkg/__init__.py",
        """
        REGISTRY = []


        class Thing:
            REGISTRY.append("built at import")

            def method(self):
                return 1
        """,
    )
    graph = graph_for(tmp_path)
    result = search(graph, ["pkg"])
    assert "pkg.Thing" in result.certain
    assert "pkg.Thing.method" not in result.possible


# --- Resolution ------------------------------------------------------------


def test_a_direct_call_resolves(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        def outer():
            return inner()


        def inner():
            return 1
        """,
    )
    graph = graph_for(tmp_path)
    assert "app.inner" in targets(graph, "app.outer")


def test_a_call_through_an_import_resolves(tmp_path: Path) -> None:
    write(tmp_path, "app.py", "from lib.mod import helper\n\n\ndef run():\n    return helper()\n")
    assert "lib.mod.helper" in targets(graph_for(tmp_path), "app.run")


def test_a_method_on_an_assigned_instance_resolves(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        class Client:
            def send(self):
                return 1


        def run():
            client = Client()
            return client.send()
        """,
    )
    assert "app.Client.send" in targets(graph_for(tmp_path), "app.run")


def test_a_method_on_a_self_attribute_resolves(tmp_path: Path) -> None:
    # The pattern a real client class uses, and the one a naive builder misses.
    write(
        tmp_path,
        "app.py",
        """
        class Transport:
            def send(self):
                return 1


        class Client:
            def __init__(self):
                self.transport = Transport()

            def run(self):
                return self.transport.send()
        """,
    )
    assert "app.Transport.send" in targets(graph_for(tmp_path), "app.Client.run")


def test_a_parameter_annotation_resolves_the_method(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        class Handler:
            def handle(self):
                return 1


        def run(handler: Handler):
            return handler.handle()
        """,
    )
    assert "app.Handler.handle" in targets(graph_for(tmp_path), "app.run")


def test_a_method_on_self_resolves_against_the_enclosing_class(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        class Thing:
            def outer(self):
                return self.inner()

            def inner(self):
                return 1
        """,
    )
    assert "app.Thing.inner" in targets(graph_for(tmp_path), "app.Thing.outer")


def test_an_inherited_method_resolves_to_the_base(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        class Base:
            def shared(self):
                return 1


        class Child(Base):
            pass


        def run():
            child = Child()
            return child.shared()
        """,
    )
    assert "app.Base.shared" in targets(graph_for(tmp_path), "app.run")


def test_constructing_a_class_runs_its_initialiser(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        class Thing:
            def __init__(self):
                self.value = risky()


        def risky():
            return 1


        def run():
            return Thing()
        """,
    )
    graph = graph_for(tmp_path)
    assert "app.Thing.__init__" in targets(graph, "app.run")
    result = search(graph, ["app.run"])
    assert "app.risky" in result.certain


def test_a_decorator_runs_at_import_so_it_is_a_call(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        def register(function):
            audit()
            return function


        def audit():
            return 1


        @register
        def handler():
            return 2
        """,
    )
    graph = graph_for(tmp_path)
    assert "app.register" in targets(graph, "app")
    result = search(graph, ["app"])
    assert "app.audit" in result.certain
    # And the decorated function itself still is not called by being defined.
    assert "app.handler" not in result.possible


# --- Overrides -------------------------------------------------------------


def test_an_override_on_a_constructed_subclass_is_a_certain_edge(
    tmp_path: Path,
) -> None:
    """The call site names the base, but this code builds the subclass."""
    write(
        tmp_path,
        "app.py",
        """
        class Base:
            def run(self):
                return 1


        class Child(Base):
            def run(self):
                return dangerous()


        def dangerous():
            return 2


        def dispatch(thing: Base):
            return thing.run()


        def main():
            return dispatch(Child())
        """,
    )
    graph = graph_for(tmp_path)
    assert kinds(graph, "app.dispatch", "app.Child.run") == {EdgeKind.STATIC}
    result = search(graph, ["app.main"])
    assert "app.dangerous" in result.certain


def test_an_override_on_a_subclass_nothing_constructs_is_a_guess(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        "app.py",
        """
        class Base:
            def run(self):
                return 1


        class Child(Base):
            def run(self):
                return 2


        def dispatch(thing: Base):
            return thing.run()
        """,
    )
    graph = graph_for(tmp_path)
    assert kinds(graph, "app.dispatch", "app.Child.run") == {EdgeKind.DYNAMIC}
    result = search(graph, ["app.dispatch"])
    # Reachable, but only possibly.
    assert "app.Child.run" in result.possible
    assert "app.Child.run" not in result.certain


# --- Dynamic dispatch and opacity -----------------------------------------


def test_getattr_on_a_known_class_yields_bounded_guesses(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        class Handler:
            def alpha(self):
                return 1

            def beta(self):
                return 2


        def run(name):
            handler = Handler()
            method = getattr(handler, name)
            return method()
        """,
    )
    graph = graph_for(tmp_path)
    reached = targets(graph, "app.run")
    # Bounded to that one class, and marked as a guess.
    assert {"app.Handler.alpha", "app.Handler.beta"} <= reached
    assert kinds(graph, "app.run", "app.Handler.alpha") <= {
        EdgeKind.DYNAMIC,
        EdgeKind.OPAQUE,
    }
    assert graph.nodes["app.run"].opaque


def test_eval_marks_a_function_opaque(tmp_path: Path) -> None:
    write(tmp_path, "app.py", "def run(code):\n    return eval(code)\n")
    assert graph_for(tmp_path).nodes["app.run"].opaque


def test_a_dynamic_import_marks_a_function_opaque(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        import importlib


        def run(name):
            return importlib.import_module(name)
        """,
    )
    assert graph_for(tmp_path).nodes["app.run"].opaque


def test_an_unknown_receiver_is_counted_as_unresolved(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        def run(thing):
            return thing.method_nobody_defines()
        """,
    )
    graph = graph_for(tmp_path)
    assert graph.quality.unresolved_call_sites >= 1
    assert graph.quality.unresolved_ratio > 0


def test_builtins_are_not_counted_as_unresolved(tmp_path: Path) -> None:
    # A quality ratio distorted by print() and len() would make every verdict
    # harder to weigh.
    write(
        tmp_path,
        "app.py",
        """
        def run(values):
            print(len(values))
            return sorted(values)
        """,
    )
    graph = graph_for(tmp_path)
    assert graph.quality.unresolved_call_sites == 0


# --- Linking ---------------------------------------------------------------


def test_a_re_exported_class_resolves_through_the_package_root(
    tmp_path: Path,
) -> None:
    """``from lib import Client`` has to find the class in ``lib.core``.

    Without this, a method call on any class imported from a package root
    silently fails to match an advisory's symbols.
    """
    library = tmp_path / "library"
    write(library, "lib/__init__.py", "from lib.core import Client\n")
    write(
        library,
        "lib/core.py",
        """
        class Client:
            def send(self):
                return vulnerable()


        def vulnerable():
            return 1
        """,
    )
    application = tmp_path / "application"
    write(
        application,
        "app.py",
        """
        from lib import Client


        def run():
            client = Client()
            return client.send()
        """,
    )

    graph = link(
        [
            build([SourceRoot(path=application)]),
            build([SourceRoot(path=library, package="lib")], package="lib"),
        ]
    )
    result = search(graph, ["app.run"])
    assert "lib.core.Client.send" in result.certain
    assert "lib.core.vulnerable" in result.certain


def test_a_wildcard_dispatch_expands_once_the_package_is_linked(
    tmp_path: Path,
) -> None:
    """The builder cannot see a dependency's methods; linking can."""
    library = tmp_path / "library"
    write(
        library,
        "lib/__init__.py",
        """
        class Handler:
            def alpha(self):
                return 1

            def beta(self):
                return 2
        """,
    )
    application = tmp_path / "application"
    write(
        application,
        "app.py",
        """
        from lib import Handler


        def run(name):
            handler = Handler()
            return getattr(handler, name)()
        """,
    )

    standalone = build([SourceRoot(path=application)])
    # Before linking, the dispatch is recorded but unresolvable.
    assert any(edge.target.endswith(".*") for edge in standalone.successors("app.run"))

    graph = link([standalone, build([SourceRoot(path=library, package="lib")], package="lib")])
    reached = targets(graph, "app.run")
    assert {"lib.Handler.alpha", "lib.Handler.beta"} <= reached


def test_first_party_code_wins_when_a_symbol_is_defined_twice(
    tmp_path: Path,
) -> None:
    write(tmp_path / "first", "shadow.py", "def run():\n    return 1\n")
    write(tmp_path / "second", "shadow.py", "def run():\n    return 2\n")
    graph = link(
        [
            build([SourceRoot(path=tmp_path / "first")]),
            build([SourceRoot(path=tmp_path / "second", package="other")], package="other"),
        ]
    )
    assert graph.nodes["shadow.run"].is_first_party


# --- Discovery and limits --------------------------------------------------


def test_test_files_are_excluded(tmp_path: Path) -> None:
    # A test suite calls everything, which would make every package look
    # fully reachable.
    write(tmp_path, "pkg/__init__.py", "")
    write(tmp_path, "pkg/tests/test_thing.py", "def test_it():\n    pass\n")
    write(tmp_path, "pkg/test_other.py", "def test_other():\n    pass\n")
    graph = graph_for(tmp_path)
    assert not any("test" in symbol for symbol in graph.nodes)


def test_test_files_can_be_included_deliberately(tmp_path: Path) -> None:
    write(tmp_path, "pkg/__init__.py", "")
    write(tmp_path, "pkg/test_other.py", "def test_other():\n    pass\n")
    graph = build([SourceRoot(path=tmp_path)], include_tests=True)
    assert "pkg.test_other.test_other" in graph.nodes


def test_an_unparsable_file_is_recorded_not_fatal(tmp_path: Path) -> None:
    write(tmp_path, "good.py", "def run():\n    return 1\n")
    write(tmp_path, "bad.py", "def broken(:\n")
    graph = graph_for(tmp_path)
    assert "good.run" in graph.nodes
    assert graph.quality.files_failed == 1
    assert graph.quality.parse_errors
    assert graph.quality.parse_error_ratio == pytest.approx(0.5)


def test_relative_imports_resolve(tmp_path: Path) -> None:
    write(tmp_path, "pkg/__init__.py", "")
    write(tmp_path, "pkg/one.py", "from .two import helper\n\n\ndef run():\n    return helper()\n")
    write(tmp_path, "pkg/two.py", "def helper():\n    return 1\n")
    graph = graph_for(tmp_path)
    assert "pkg.two.helper" in targets(graph, "pkg.one.run")


def test_a_deeply_relative_import_resolves(tmp_path: Path) -> None:
    write(tmp_path, "pkg/__init__.py", "")
    write(tmp_path, "pkg/sub/__init__.py", "")
    write(
        tmp_path,
        "pkg/sub/mod.py",
        "from ..top import helper\n\n\ndef run():\n    return helper()\n",
    )
    write(tmp_path, "pkg/top.py", "def helper():\n    return 1\n")
    graph = graph_for(tmp_path)
    assert "pkg.top.helper" in targets(graph, "pkg.sub.mod.run")


def test_the_graph_records_its_package_and_builder_version(tmp_path: Path) -> None:
    write(tmp_path, "lib.py", "def run():\n    return 1\n")
    graph = build([SourceRoot(path=tmp_path, package="lib")], package="lib", version="1.2.3")
    assert graph.package == "lib"
    assert graph.version == "1.2.3"
    # The builder version keys the cache, so a rebuild can roll out gradually.
    assert graph.builder_version


def test_an_oversized_file_is_skipped(tmp_path: Path) -> None:
    write(tmp_path, "small.py", "def run():\n    return 1\n")
    (tmp_path / "huge.py").write_text("x = 1\n" * (MAX_FILE_BYTES // 5), encoding="utf-8")
    graph = graph_for(tmp_path)
    assert "small.run" in graph.nodes
    assert "huge" not in graph.nodes


def test_building_an_empty_directory_yields_an_empty_graph(tmp_path: Path) -> None:
    graph = graph_for(tmp_path)
    assert len(graph) == 0
    assert graph.quality.call_sites == 0
    assert graph.quality.unresolved_ratio == 0.0


def test_node_kinds_are_recorded(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        """
        class Thing:
            def method(self):
                return 1


        def function():
            return 2
        """,
    )
    graph = graph_for(tmp_path)
    assert graph.nodes["app"].kind is SymbolKind.MODULE
    assert graph.nodes["app.Thing"].kind is SymbolKind.CLASS
    assert graph.nodes["app.Thing.method"].kind is SymbolKind.METHOD
    assert graph.nodes["app.function"].kind is SymbolKind.FUNCTION
