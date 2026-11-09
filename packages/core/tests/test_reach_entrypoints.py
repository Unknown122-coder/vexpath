"""Entry-point detection.

The choice of starting points decides every verdict, so these tests cover each
source and the precedence between them. The fallback matters most: when nothing
is declared, the analysis must say it guessed rather than present an inferred
set as knowledge.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from vexpath_core.enums import EntryPointSource, SymbolKind
from vexpath_core.reach.entrypoints import (
    choose,
    detect_in_module,
    from_config,
    from_package_metadata,
    is_inferred,
    public_fallback,
)
from vexpath_core.reach.graph import CallGraph, Node


def _detect(source: str, module: str = "app") -> dict[str, EntryPointSource]:
    tree = ast.parse(textwrap.dedent(source).lstrip("\n"))
    return {entry.symbol: entry.source for entry in detect_in_module(tree, module)}


def _graph(*symbols: tuple[str, SymbolKind, str | None]) -> CallGraph:
    return CallGraph(
        nodes={symbol: Node(symbol, kind, package=package) for symbol, kind, package in symbols}
    )


# --- Declared starting points ---------------------------------------------


def test_a_main_guard_makes_the_module_an_entry_point() -> None:
    found = _detect(
        """
        def run():
            return 1


        if __name__ == "__main__":
            run()
        """
    )
    assert found["app"] is EntryPointSource.DUNDER_MAIN


def test_a_dunder_main_module_is_an_entry_point() -> None:
    assert _detect("run()\n", module="pkg.__main__")["pkg.__main__"] is (
        EntryPointSource.DUNDER_MAIN
    )


def test_console_scripts_are_read_from_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent(
            """
            [project]
            name = "example"

            [project.scripts]
            example = "example.cli:main"

            [project.entry-points."example.plugins"]
            thing = "example.plugin:register"
            """
        ).lstrip(),
        encoding="utf-8",
    )
    found = {entry.symbol for entry in from_package_metadata(tmp_path)}
    assert "example.cli.main" in found
    assert "example.plugin.register" in found


def test_poetry_scripts_are_read_too(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent(
            """
            [tool.poetry.scripts]
            example = "example.cli:main"
            """
        ).lstrip(),
        encoding="utf-8",
    )
    assert {entry.symbol for entry in from_package_metadata(tmp_path)} == {"example.cli.main"}


def test_setup_cfg_console_scripts_are_read(tmp_path: Path) -> None:
    (tmp_path / "setup.cfg").write_text(
        textwrap.dedent(
            """
            [options.entry_points]
            console_scripts =
                example = example.cli:main
            """
        ).lstrip(),
        encoding="utf-8",
    )
    assert {entry.symbol for entry in from_package_metadata(tmp_path)} == {"example.cli.main"}


def test_a_setup_py_project_contributes_nothing_because_it_is_not_executed(
    tmp_path: Path,
) -> None:
    # Running an analysed project's setup.py would be remote code execution.
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup(entry_points={'console_scripts': ['x=y:z']})\n",
        encoding="utf-8",
    )
    assert from_package_metadata(tmp_path) == []


def test_a_malformed_pyproject_is_survivable(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("this is not = = toml\n", encoding="utf-8")
    assert from_package_metadata(tmp_path) == []


def test_configured_targets_are_normalised() -> None:
    found = from_config(["app.main:create_app", "app.worker", "  "])
    assert [entry.symbol for entry in found] == ["app.main.create_app", "app.worker"]
    assert all(entry.source is EntryPointSource.CONFIG for entry in found)


# --- Framework conventions -------------------------------------------------


def test_web_routes_are_entry_points() -> None:
    found = _detect(
        """
        from fastapi import FastAPI

        app = FastAPI()


        @app.get("/items")
        def list_items():
            return []


        @router.post("/items")
        def create_item():
            return {}
        """
    )
    assert found["app.list_items"] is EntryPointSource.FRAMEWORK
    assert found["app.create_item"] is EntryPointSource.FRAMEWORK
    # The module-level application object means a server imports this module.
    assert found["app"] is EntryPointSource.FRAMEWORK


def test_background_tasks_are_entry_points() -> None:
    found = _detect(
        """
        @shared_task
        def nightly():
            return 1


        @celery.task(bind=True)
        def other(self):
            return 2
        """
    )
    assert "app.nightly" in found
    assert "app.other" in found


def test_command_line_commands_are_entry_points() -> None:
    found = _detect(
        """
        @cli.command()
        def serve():
            return 1
        """
    )
    assert "app.serve" in found


def test_a_serverless_handler_is_an_entry_point() -> None:
    found = _detect("def handler(event, context):\n    return 1\n")
    assert found["app.handler"] is EntryPointSource.FRAMEWORK


def test_a_django_management_command_is_entered_through_handle() -> None:
    found = _detect(
        """
        class Command:
            def handle(self, *args, **options):
                return 1
        """,
        module="myapp.management.commands.sync",
    )
    assert "myapp.management.commands.sync.Command.handle" in found


def test_a_url_configuration_is_an_entry_point() -> None:
    # It names its views in data rather than decorating them, so the module is
    # the starting point and its imports carry the search onward.
    found = _detect("urlpatterns = []\n", module="myapp.urls")
    assert found["myapp.urls"] is EntryPointSource.FRAMEWORK


def test_a_method_named_like_a_handler_is_not_mistaken_for_one() -> None:
    # Only module-level functions match by name; a method called main is
    # ordinary code.
    found = _detect(
        """
        class Thing:
            def main(self):
                return 1
        """
    )
    assert "app.Thing.main" not in found


def test_test_frameworks_are_deliberately_not_detected() -> None:
    # A test harness calls everything, which would make every package look
    # fully reachable.
    found = _detect(
        """
        import pytest


        @pytest.fixture
        def thing():
            return 1
        """
    )
    assert "app.thing" not in found


# --- Choosing --------------------------------------------------------------


def test_configuration_beats_everything_else(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project.scripts]\nexample = "app.cli:main"\n', encoding="utf-8"
    )
    graph = _graph(
        ("app.cli.main", SymbolKind.FUNCTION, None),
        ("app.chosen", SymbolKind.FUNCTION, None),
    )
    symbols, info = choose(graph, configured=["app.chosen"], root=tmp_path)
    assert info.source is EntryPointSource.CONFIG
    assert "app.chosen" in symbols


def test_the_public_fallback_is_used_when_nothing_is_declared() -> None:
    graph = _graph(
        ("app", SymbolKind.MODULE, None),
        ("app.run", SymbolKind.FUNCTION, None),
        ("app._private", SymbolKind.FUNCTION, None),
    )
    symbols, info = choose(graph)
    assert info.source is EntryPointSource.FALLBACK_PUBLIC
    assert "app.run" in symbols
    # Private names are not a public surface.
    assert "app._private" not in symbols


def test_the_fallback_is_reported_as_inferred() -> None:
    assert is_inferred(EntryPointSource.FALLBACK_PUBLIC)
    assert not is_inferred(EntryPointSource.CONFIG)
    assert not is_inferred(EntryPointSource.PACKAGE_METADATA)


def test_dependency_code_is_never_an_entry_point() -> None:
    # A library has no entry points of its own; only the project does.
    graph = _graph(
        ("lib", SymbolKind.MODULE, "lib"),
        ("lib.run", SymbolKind.FUNCTION, "lib"),
    )
    assert public_fallback(graph) == []


def test_first_party_modules_are_always_included() -> None:
    """Importing a module runs it, whatever the nominal entry point is."""
    graph = _graph(
        ("app", SymbolKind.MODULE, None),
        ("app.helpers", SymbolKind.MODULE, None),
        ("app.run", SymbolKind.FUNCTION, None),
        ("lib", SymbolKind.MODULE, "lib"),
    )
    symbols, _ = choose(graph, configured=["app.run"])
    assert {"app", "app.helpers", "app.run"} <= set(symbols)
    assert "lib" not in symbols


def test_a_stale_configured_entry_point_does_not_count_as_a_source() -> None:
    graph = _graph(("app.run", SymbolKind.FUNCTION, None))
    symbols, info = choose(graph, configured=["app.gone"])
    # The configured symbol no longer exists, so the set falls back and says so
    # rather than reporting a precise source it did not actually use.
    assert info.source is EntryPointSource.FALLBACK_PUBLIC
    assert "app.gone" not in symbols


def test_the_reported_count_matches_the_symbols_returned() -> None:
    graph = _graph(
        ("app", SymbolKind.MODULE, None),
        ("app.run", SymbolKind.FUNCTION, None),
    )
    symbols, info = choose(graph, configured=["app.run"])
    assert info.count == len(symbols)
