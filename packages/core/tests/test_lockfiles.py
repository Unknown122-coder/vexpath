"""Lockfile parsers.

Each format is checked for the three things the rest of the pipeline relies on:
exact versions, whether a dependency is direct, and the dependency graph where
the format records one. Where a format records no graph, the parser has to say
so rather than return an empty one, because an empty graph and an unrecorded
graph look identical downstream.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sscp_core.enums import ComponentScope
from sscp_core.sbom.lockfiles import (
    LOCKFILE_PRIORITY,
    LockfileError,
    find_lockfiles,
    parse_lockfile,
)


def _write(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return path


def _by_name(result: object) -> dict[str, object]:
    return {package.name: package for package in result.packages}  # type: ignore[attr-defined]


# --- requirements.txt ------------------------------------------------------


def test_pinned_requirements_are_parsed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "requirements.txt",
        """
        # A comment
        requests==2.31.0
        Flask-SQLAlchemy==3.1.1  # trailing comment
        urllib3==1.26.17 ; python_version < "3.12"
        pytest[testing]==8.3.3
        --index-url https://pypi.org/simple
        """,
    )
    result = parse_lockfile(path)
    packages = _by_name(result)
    assert set(packages) == {"requests", "flask-sqlalchemy", "urllib3", "pytest"}
    assert packages["requests"].version == "2.31.0"  # type: ignore[attr-defined]
    # Extras and environment markers are not part of the identity.
    assert packages["pytest"].version == "8.3.3"  # type: ignore[attr-defined]
    assert packages["flask-sqlalchemy"].version == "3.1.1"  # type: ignore[attr-defined]


def test_unpinned_requirements_are_refused_with_the_fix(tmp_path: Path) -> None:
    """Analysing a version that may not be what installs is worse than stopping."""
    path = _write(tmp_path, "requirements.txt", "requests>=2.31.0\nflask\n")
    with pytest.raises(LockfileError) as exc_info:
        parse_lockfile(path)
    message = str(exc_info.value)
    assert "unpinned" in message
    assert "uv lock" in message


def test_a_flat_requirements_file_says_it_has_no_graph(tmp_path: Path) -> None:
    path = _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    result = parse_lockfile(path)
    assert not result.has_dependency_graph
    assert any("no dependency relationships" in note for note in result.notes)


def test_a_pyproject_beside_it_identifies_direct_dependencies(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pyproject.toml",
        """
        [project]
        name = "example"
        dependencies = ["requests>=2.0"]
        """,
    )
    path = _write(tmp_path, "requirements.txt", "requests==2.31.0\nurllib3==1.26.17\n")
    result = parse_lockfile(path)
    packages = _by_name(result)
    assert packages["requests"].direct  # type: ignore[attr-defined]
    assert not packages["urllib3"].direct  # type: ignore[attr-defined]


def test_without_a_pyproject_directness_is_unknown_and_declared(tmp_path: Path) -> None:
    path = _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    result = parse_lockfile(path)
    assert all(package.direct for package in result.packages)
    assert any("could not be distinguished" in note for note in result.notes)


def test_a_setup_py_project_is_parsed_not_executed(tmp_path: Path) -> None:
    # Executing a setup.py from an analysed project would be remote code
    # execution, so the file is only ever noted, never run.
    _write(tmp_path, "setup.py", "import os; os.system('echo pwned')\nsetup()\n")
    path = _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    result = parse_lockfile(path)
    assert any("never executed" in note for note in result.notes)


def test_backslash_continuations_are_joined(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "requirements.txt",
        """
        requests==2.31.0 \\
            --hash=sha256:deadbeef
        """,
    )
    assert _by_name(parse_lockfile(path))["requests"].version == "2.31.0"  # type: ignore[attr-defined]


def test_editable_installs_are_skipped_and_counted(tmp_path: Path) -> None:
    path = _write(tmp_path, "requirements.txt", "-e .\nrequests==2.31.0\n")
    result = parse_lockfile(path)
    assert set(_by_name(result)) == {"requests"}
    assert any("editable" in note for note in result.notes)


# --- uv.lock ---------------------------------------------------------------


def test_uv_lock_gives_versions_directness_and_a_graph(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "uv.lock",
        """
        version = 1

        [[package]]
        name = "example"
        version = "0.1.0"
        source = { virtual = "." }
        dependencies = [{ name = "requests" }]

        [package.dev-dependencies]
        dev = [{ name = "pytest" }]

        [[package]]
        name = "requests"
        version = "2.31.0"
        source = { registry = "https://pypi.org/simple" }
        dependencies = [{ name = "urllib3" }, { name = "certifi" }]

        [[package]]
        name = "urllib3"
        version = "1.26.17"
        source = { registry = "https://pypi.org/simple" }

        [[package]]
        name = "certifi"
        version = "2023.7.22"
        source = { registry = "https://pypi.org/simple" }

        [[package]]
        name = "pytest"
        version = "8.3.3"
        source = { registry = "https://pypi.org/simple" }
        """,
    )
    result = parse_lockfile(path)
    packages = _by_name(result)

    # The project itself is not one of its own dependencies.
    assert "example" not in packages
    assert packages["requests"].direct  # type: ignore[attr-defined]
    assert not packages["urllib3"].direct  # type: ignore[attr-defined]
    assert packages["requests"].dependencies == ("urllib3", "certifi")  # type: ignore[attr-defined]
    assert packages["pytest"].scope is ComponentScope.DEV  # type: ignore[attr-defined]
    assert result.has_dependency_graph


# --- poetry.lock -----------------------------------------------------------


def test_poetry_lock_reads_groups_and_dependencies(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "poetry.lock",
        """
        [[package]]
        name = "requests"
        version = "2.31.0"
        groups = ["main"]

        [package.dependencies]
        urllib3 = ">=1.21.1"
        python = "^3.12"

        [[package]]
        name = "pytest"
        version = "8.3.3"
        groups = ["dev"]
        """,
    )
    result = parse_lockfile(path)
    packages = _by_name(result)
    assert packages["requests"].scope is ComponentScope.RUNTIME  # type: ignore[attr-defined]
    assert packages["pytest"].scope is ComponentScope.DEV  # type: ignore[attr-defined]
    # 'python' is a constraint on the interpreter, not a package.
    assert packages["requests"].dependencies == ("urllib3",)  # type: ignore[attr-defined]


def test_poetry_lock_falls_back_to_the_old_category_field(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "poetry.lock",
        """
        [[package]]
        name = "pytest"
        version = "8.3.3"
        category = "dev"
        """,
    )
    assert _by_name(parse_lockfile(path))["pytest"].scope is ComponentScope.DEV  # type: ignore[attr-defined]


# --- pdm.lock --------------------------------------------------------------


def test_pdm_lock_parses_requirement_strings(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "pdm.lock",
        """
        [[package]]
        name = "requests"
        version = "2.31.0"
        groups = ["default"]
        dependencies = ["urllib3>=1.21.1", "certifi>=2017.4.17"]

        [[package]]
        name = "pytest"
        version = "8.3.3"
        groups = ["test"]
        """,
    )
    packages = _by_name(parse_lockfile(path))
    assert packages["requests"].dependencies == ("urllib3", "certifi")  # type: ignore[attr-defined]
    assert packages["pytest"].scope is ComponentScope.DEV  # type: ignore[attr-defined]


# --- Pipfile.lock ----------------------------------------------------------


def test_pipfile_lock_strips_the_equality_prefix(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "Pipfile.lock",
        """
        {
          "default": {"requests": {"version": "==2.31.0"}},
          "develop": {"pytest": {"version": "==8.3.3"}}
        }
        """,
    )
    result = parse_lockfile(path)
    packages = _by_name(result)
    assert packages["requests"].version == "2.31.0"  # type: ignore[attr-defined]
    assert packages["pytest"].scope is ComponentScope.DEV  # type: ignore[attr-defined]
    assert any("no dependency relationships" in note for note in result.notes)


def test_pipfile_entries_without_a_pin_are_skipped_and_reported(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "Pipfile.lock",
        """
        {"default": {"requests": {"version": "==2.31.0"}, "flask": {"ref": "abc123"}}}
        """,
    )
    result = parse_lockfile(path)
    assert set(_by_name(result)) == {"requests"}
    assert any("no pinned version" in note for note in result.notes)


# --- package-lock.json -----------------------------------------------------


def test_package_lock_v3_gives_scopes_directness_and_a_graph(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "package-lock.json",
        """
        {
          "name": "example",
          "lockfileVersion": 3,
          "packages": {
            "": {
              "dependencies": {"lodash": "^4.17.20"},
              "devDependencies": {"jest": "^29.0.0"}
            },
            "node_modules/lodash": {"version": "4.17.20", "dependencies": {"ms": "^2.0.0"}},
            "node_modules/ms": {"version": "2.1.3"},
            "node_modules/jest": {"version": "29.7.0", "dev": true},
            "node_modules/lodash/node_modules/ms": {"version": "2.0.0", "optional": true}
          }
        }
        """,
    )
    result = parse_lockfile(path)
    assert result.ecosystem == "npm"
    packages = {(p.name, p.version): p for p in result.packages}
    assert ("lodash", "4.17.20") in packages
    assert packages[("lodash", "4.17.20")].direct
    assert packages[("jest", "29.7.0")].scope is ComponentScope.DEV
    assert packages[("ms", "2.0.0")].scope is ComponentScope.OPTIONAL
    # Nested paths name the inner package, not the path.
    assert ("ms", "2.1.3") in packages
    assert packages[("lodash", "4.17.20")].dependencies == ("ms",)


def test_package_lock_v1_is_refused_with_the_remedy(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "package-lock.json",
        """
        {"name": "example", "lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.20"}}}
        """,
    )
    with pytest.raises(LockfileError, match="npm 7 or later"):
        parse_lockfile(path)


# --- pnpm-lock.yaml --------------------------------------------------------


def test_pnpm_lock_v9_reads_snapshots_for_dependencies(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "pnpm-lock.yaml",
        """
        lockfileVersion: '9.0'

        importers:
          .:
            dependencies:
              lodash:
                specifier: ^4.17.20
                version: 4.17.20
            devDependencies:
              jest:
                specifier: ^29.0.0
                version: 29.7.0

        packages:
          lodash@4.17.20:
            resolution: {integrity: sha512-abc}
          jest@29.7.0:
            resolution: {integrity: sha512-def}
          ms@2.1.3:
            resolution: {integrity: sha512-ghi}

        snapshots:
          lodash@4.17.20:
            dependencies:
              ms: 2.1.3
          jest@29.7.0: {}
          ms@2.1.3: {}
        """,
    )
    result = parse_lockfile(path)
    packages = _by_name(result)
    assert packages["lodash"].version == "4.17.20"  # type: ignore[attr-defined]
    assert packages["lodash"].direct  # type: ignore[attr-defined]
    assert packages["lodash"].dependencies == ("ms",)  # type: ignore[attr-defined]
    assert packages["jest"].scope is ComponentScope.DEV  # type: ignore[attr-defined]
    assert not packages["ms"].direct  # type: ignore[attr-defined]


def test_pnpm_lock_v6_reads_dependencies_in_place(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "pnpm-lock.yaml",
        """
        lockfileVersion: '6.0'

        dependencies:
          lodash:
            specifier: ^4.17.20
            version: 4.17.20

        packages:
          /lodash@4.17.20:
            resolution: {integrity: sha512-abc}
            dependencies:
              ms: 2.1.3
          /ms@2.1.3:
            resolution: {integrity: sha512-ghi}
        """,
    )
    packages = _by_name(parse_lockfile(path))
    assert packages["lodash"].dependencies == ("ms",)  # type: ignore[attr-defined]


def test_pnpm_scoped_and_peer_qualified_keys_are_split_correctly(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "pnpm-lock.yaml",
        """
        lockfileVersion: '9.0'
        packages:
          '@babel/core@7.23.0(peer@1.0.0)':
            resolution: {integrity: sha512-abc}
        """,
    )
    packages = _by_name(parse_lockfile(path))
    # The peer suffix identifies a resolution variant, not a version.
    assert packages["@babel/core"].version == "7.23.0"  # type: ignore[attr-defined]


def test_an_unsupported_pnpm_version_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, "pnpm-lock.yaml", "lockfileVersion: '5.4'\npackages: {}\n")
    with pytest.raises(LockfileError, match="versions 6 and 9 are supported"):
        parse_lockfile(path)


# --- Discovery -------------------------------------------------------------


def test_lockfiles_are_found_in_preference_order(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    _write(tmp_path, "uv.lock", "version = 1\n")
    found = find_lockfiles(tmp_path)
    # A resolver's output beats a flat requirements file, because it carries a
    # dependency graph.
    assert found[0].name == "uv.lock"
    assert LOCKFILE_PRIORITY.index("uv.lock") < LOCKFILE_PRIORITY.index("requirements.txt")


def test_only_the_project_root_is_searched(tmp_path: Path) -> None:
    # Walking the tree would pick up lockfiles from vendored copies and test
    # fixtures, inflating the inventory with packages nothing uses.
    nested = tmp_path / "vendor" / "other"
    nested.mkdir(parents=True)
    _write(nested, "uv.lock", "version = 1\n")
    assert find_lockfiles(tmp_path) == []


def test_alternative_requirements_names_are_found(tmp_path: Path) -> None:
    _write(tmp_path, "requirements-dev.txt", "pytest==8.3.3\n")
    found = find_lockfiles(tmp_path)
    assert [path.name for path in found] == ["requirements-dev.txt"]


def test_an_unsupported_lockfile_names_the_alternatives(tmp_path: Path) -> None:
    path = _write(tmp_path, "yarn.lock", "# yarn lockfile v1\n")
    with pytest.raises(LockfileError) as exc_info:
        parse_lockfile(path)
    assert "Syft" in str(exc_info.value)


def test_malformed_toml_is_reported_clearly(tmp_path: Path) -> None:
    path = _write(tmp_path, "uv.lock", "this is not = = toml\n")
    with pytest.raises(LockfileError, match="not readable TOML"):
        parse_lockfile(path)
