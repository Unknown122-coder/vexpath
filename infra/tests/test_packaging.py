"""Every package declares what it imports, and the layers point one way.

This exists because of a bug it would have caught. The command-line tool
imported ``vexpath_platform`` for three constants about the shape of an API
key. Inside the workspace every package is installed, so it worked; a
published ``vexpath`` wheel was broken on install with
``ModuleNotFoundError: No module named 'vexpath_platform'``. Nothing in the
test suite could see it, because the test suite runs in the workspace.

So these tests read the imports out of the source and compare them with the
declared dependencies. They also pin the direction of the layering, because
the fix for that bug involved moving a module between packages and the wrong
direction would have been just as installable and much harder to undo later.

They do not replace building a wheel and installing it into an empty
environment, which is what found the bug. ``make dist`` does that.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: Every workspace member, and where its source lives.
PACKAGES = {
    "vexpath-core": ROOT / "packages" / "core",
    "vexpath-platform": ROOT / "packages" / "platform",
    "vexpath-db": ROOT / "packages" / "db",
    "vexpath": ROOT / "packages" / "cli",
    "vexpath-api": ROOT / "apps" / "api",
    "vexpath-worker": ROOT / "apps" / "worker",
}

#: Import name to distribution name.
DISTRIBUTIONS = {
    "vexpath_core": "vexpath-core",
    "vexpath_platform": "vexpath-platform",
    "vexpath_db": "vexpath-db",
    "vexpath": "vexpath",
    "vexpath_api": "vexpath-api",
    "vexpath_worker": "vexpath-worker",
}

#: What each layer may depend on. The core is the bottom and depends on no
#: workspace package; the platform and the database layer sit on it; the
#: command line and the two applications sit on those. A dependency pointing
#: the other way -- the core reaching for settings, or the platform importing
#: an application -- would be installable and wrong, and this is where it is
#: refused.
ALLOWED = {
    "vexpath-core": set(),
    "vexpath-platform": {"vexpath-core"},
    "vexpath-db": {"vexpath-core"},
    "vexpath": {"vexpath-core"},
    "vexpath-api": {"vexpath-core", "vexpath-platform", "vexpath-db"},
    "vexpath-worker": {"vexpath-core", "vexpath-platform", "vexpath-db"},
}


def _manifest(directory: Path) -> dict[str, object]:
    document: dict[str, object] = tomllib.loads(
        (directory / "pyproject.toml").read_text(encoding="utf-8")
    )
    return document


def _declared(directory: Path) -> set[str]:
    project = _manifest(directory)["project"]
    assert isinstance(project, dict)
    requirements: list[str] = list(project.get("dependencies", []))
    for extra in (project.get("optional-dependencies") or {}).values():
        requirements.extend(extra)
    return {name for name in map(_requirement_name, requirements) if name}


def _requirement_name(requirement: str) -> str:
    """The distribution name from a PEP 508 requirement.

    Enough of the grammar for a name: everything up to the first character
    that cannot be part of one, normalised the way PyPI normalises.
    """
    name = ""
    for character in requirement.strip():
        if character.isalnum() or character in "-._":
            name += character
        else:
            break
    return name.lower().replace("_", "-")


def _imported(directory: Path) -> set[str]:
    """Which workspace packages this one's source imports."""
    found: set[str] = set()
    for path in (directory / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
    return {DISTRIBUTIONS[name] for name in found if name in DISTRIBUTIONS}


@pytest.mark.parametrize("name", sorted(PACKAGES))
def test_every_workspace_import_is_declared(name: str) -> None:
    directory = PACKAGES[name]
    own = name
    missing = {
        imported
        for imported in _imported(directory)
        if imported != own and imported not in _declared(directory)
    }
    # The bug this catches: it works in the workspace, where everything is
    # installed, and fails on install from a wheel.
    assert not missing, (
        f"{name} imports {sorted(missing)} without declaring it; a published "
        f"wheel would fail to import"
    )


@pytest.mark.parametrize("name", sorted(PACKAGES))
def test_the_layers_point_one_way(name: str) -> None:
    workspace = {dependency for dependency in _declared(PACKAGES[name]) if dependency in PACKAGES}
    forbidden = workspace - ALLOWED[name]
    # A dependency pointing the wrong way is installable and wrong: the core
    # reaching for settings, or the platform importing an application, would
    # both work in the workspace and both be a mistake that is painful to
    # undo once something depends on it.
    assert not forbidden, f"{name} must not depend on {sorted(forbidden)}"


def test_the_core_depends_on_no_workspace_package() -> None:
    # Stated separately because it is the rule the architecture rests on: the
    # analysis package must be usable without a framework, a database or a
    # web server anywhere near it.
    assert not {d for d in _declared(PACKAGES["vexpath-core"]) if d in PACKAGES}


def test_the_core_imports_no_framework_or_database() -> None:
    forbidden = {"fastapi", "starlette", "sqlalchemy", "alembic", "psycopg", "uvicorn", "typer"}
    imported: set[str] = set()
    for path in (PACKAGES["vexpath-core"] / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
    # The rule that keeps the analysis runnable from a laptop with nothing
    # else installed, and testable without a database.
    assert not (imported & forbidden), sorted(imported & forbidden)


@pytest.mark.parametrize("name", sorted(PACKAGES))
def test_every_package_shares_one_version(name: str) -> None:
    project = _manifest(PACKAGES[name])["project"]
    assert isinstance(project, dict)
    core = _manifest(PACKAGES["vexpath-core"])["project"]
    assert isinstance(core, dict)
    # They are released together and depend on each other by name without a
    # version bound, so a published set with mixed versions would resolve to
    # whatever PyPI had. One version for all of them is the only arrangement
    # that cannot go wrong.
    assert project["version"] == core["version"]


@pytest.mark.parametrize("name", sorted(PACKAGES))
def test_every_package_is_apache_licensed_with_the_root_licence(name: str) -> None:
    project = _manifest(PACKAGES[name])["project"]
    assert isinstance(project, dict)
    assert project["license"] == "Apache-2.0"
    # One LICENSE file at the root, referenced by each package, so a wheel
    # carries the licence it claims.
    assert project["license-files"]


@pytest.mark.parametrize("name", sorted(PACKAGES))
def test_every_workspace_dependency_is_pinned_to_this_version(name: str) -> None:
    """A sibling package is required at exactly this version, not loosely.

    These are released together and each imports the others' internals.
    Unbounded, ``pip install vexpath==0.0.1`` could resolve
    ``vexpath-core==9.9.9`` and import a module that moved -- the kind of
    failure that only appears for somebody installing from PyPI, which is
    nobody who works on this.
    """
    project = _manifest(PACKAGES[name])["project"]
    assert isinstance(project, dict)
    version = project["version"]
    for requirement in project.get("dependencies", []):
        # Compared by parsed name, not by prefix: "vexpath" is a prefix of
        # "vexpath-core", and a prefix match would read every core dependency
        # as a malformed vexpath one.
        sibling = _requirement_name(requirement)
        if sibling in PACKAGES:
            assert requirement == f"{sibling}=={version}", requirement


def test_the_command_line_does_not_pull_in_the_server() -> None:
    declared = _declared(PACKAGES["vexpath"])
    # `pipx install vexpath` should not install the platform's settings,
    # logging and request machinery, nor a database driver.
    for unwanted in ("vexpath-platform", "vexpath-db", "vexpath-api", "fastapi", "sqlalchemy"):
        assert unwanted not in declared, unwanted


def test_the_command_line_has_a_console_script() -> None:
    project = _manifest(PACKAGES["vexpath"])["project"]
    assert isinstance(project, dict)
    scripts = project["scripts"]
    assert isinstance(scripts, dict)
    assert scripts["vexpath"] == "vexpath.main:app"
