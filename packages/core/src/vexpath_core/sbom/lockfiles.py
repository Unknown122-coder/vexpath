"""Lockfile parsers.

Lockfiles are parsed natively rather than through an external generator
(ADR-0009) because reachability needs two things a heuristic inventory cannot
give: the exact resolved version of every package, and the dependency graph
that explains why a transitive package is present at all.

Every parser here reads a declarative file with a standard library parser:
TOML, JSON or YAML. None of them executes anything. `setup.py` is never run,
and a project's own code is never imported.

Supported formats:

| File | Ecosystem | Dependency graph |
|---|---|---|
| ``uv.lock`` | PyPI | yes |
| ``poetry.lock`` | PyPI | yes |
| ``pdm.lock`` | PyPI | yes |
| ``Pipfile.lock`` | PyPI | no, the format does not record it |
| ``requirements.txt`` (fully pinned) | PyPI | no, the format does not record it |
| ``package-lock.json`` (v2, v3) | npm | yes |
| ``pnpm-lock.yaml`` (v6, v9) | npm | yes |

``yarn.lock`` is deliberately absent: its bespoke format is left to the Syft
wrapper rather than maintained here.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from vexpath_core.enums import ComponentScope
from vexpath_core.purl import normalise_name

#: Lockfiles are searched for in this order, and the first one found wins. The
#: order prefers formats that record a dependency graph, and prefers a modern
#: resolver's output over a flat requirements file.
LOCKFILE_PRIORITY: tuple[str, ...] = (
    "uv.lock",
    "poetry.lock",
    "pdm.lock",
    "Pipfile.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "requirements.txt",
)

_REQUIREMENT = re.compile(
    r"""^
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)      # project name
    (?:\[(?P<extras>[^\]]*)\])?               # optional extras
    \s*==\s*
    (?P<version>[^\s;#]+)                     # pinned version
    """,
    re.VERBOSE,
)

#: pnpm package keys look like ``/@babel/core@7.23.0(peer@1.0.0)``. The peer
#: suffix identifies a resolution variant, not a different package version.
_PNPM_PEER_SUFFIX = re.compile(r"\(.*\)$")


class LockfileError(Exception):
    """Raised when a lockfile cannot be used for analysis.

    The message always says what to do about it. A lockfile that cannot be
    parsed is a stop, not a reason to fall back to guessing at versions.
    """


@dataclass(frozen=True, slots=True)
class LockedPackage:
    """One resolved package from a lockfile."""

    name: str
    version: str
    ecosystem: str
    scope: ComponentScope = ComponentScope.RUNTIME
    #: True when the project depends on this package directly.
    direct: bool = False
    #: Names of the packages this one depends on, normalised.
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LockfileResult:
    """Everything one lockfile yielded."""

    path: Path
    kind: str
    ecosystem: str
    packages: tuple[LockedPackage, ...]
    #: Limitations of this particular file, carried through to the SBOM so a
    #: reader knows what the inventory could not determine.
    notes: tuple[str, ...] = field(default=())

    @property
    def has_dependency_graph(self) -> bool:
        return any(package.dependencies for package in self.packages)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def find_lockfiles(root: Path) -> list[Path]:
    """Return the lockfiles in ``root``, best first.

    Only the project root is searched. Walking a tree would pick up lockfiles
    belonging to vendored copies, test fixtures and example projects, and
    silently inflate the inventory with packages the application never uses.
    """
    found = [root / name for name in LOCKFILE_PRIORITY if (root / name).is_file()]
    if not found:
        # A requirements file under a conventional name is common enough to be
        # worth finding, but only at the root and only if nothing better exists.
        found.extend(sorted(root.glob("requirements*.txt")))
    return found


def parse_lockfile(path: Path) -> LockfileResult:
    """Parse one lockfile.

    Raises:
        LockfileError: if the format is unsupported or the file is unusable.
    """
    parsers = {
        "uv.lock": _parse_uv_lock,
        "poetry.lock": _parse_poetry_lock,
        "pdm.lock": _parse_pdm_lock,
        "Pipfile.lock": _parse_pipfile_lock,
        "package-lock.json": _parse_package_lock_json,
        "pnpm-lock.yaml": _parse_pnpm_lock,
    }
    parser = parsers.get(path.name)
    if parser is None:
        if path.name.startswith("requirements") and path.suffix == ".txt":
            return _parse_requirements_txt(path)
        msg = (
            f"unsupported lockfile {path.name!r}. Supported: "
            f"{', '.join(LOCKFILE_PRIORITY)}. For other ecosystems, generate a "
            f"CycloneDX document with Syft and pass it with --sbom."
        )
        raise LockfileError(msg)
    return parser(path)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            data: dict[str, Any] = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        msg = f"{path.name} is not readable TOML: {exc}"
        raise LockfileError(msg) from exc
    return data


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = f"{path.name} is not readable JSON: {exc}"
        raise LockfileError(msg) from exc


def _parse_uv_lock(path: Path) -> LockfileResult:
    """Parse ``uv.lock``.

    uv records the project itself as a package whose dependencies are the
    direct ones, which is how directness is determined without reading
    ``pyproject.toml`` as well.
    """
    data = _load_toml(path)
    entries = data.get("package", [])
    if not isinstance(entries, list):
        msg = "uv.lock has no package table"
        raise LockfileError(msg)

    # An entry sourced from the local directory is the project under analysis,
    # not a dependency of it.
    root_names: set[str] = set()
    dev_names: set[str] = set()
    for entry in entries:
        source = entry.get("source", {})
        if isinstance(source, dict) and ("virtual" in source or "editable" in source):
            root_names.update(_uv_dependency_names(entry.get("dependencies", [])))
            groups = entry.get("dev-dependencies", {})
            if isinstance(groups, dict):
                for members in groups.values():
                    dev_names.update(_uv_dependency_names(members))

    packages: list[LockedPackage] = []
    for entry in entries:
        name = entry.get("name")
        version = entry.get("version")
        if not name or not version:
            continue
        source = entry.get("source", {})
        if isinstance(source, dict) and ("virtual" in source or "editable" in source):
            continue
        normalised = normalise_name("PyPI", str(name))
        packages.append(
            LockedPackage(
                name=normalised,
                version=str(version),
                ecosystem="PyPI",
                scope=ComponentScope.DEV if normalised in dev_names else ComponentScope.RUNTIME,
                direct=normalised in root_names or normalised in dev_names,
                dependencies=_uv_dependency_names(entry.get("dependencies", [])),
            )
        )
    return LockfileResult(path=path, kind="uv.lock", ecosystem="PyPI", packages=tuple(packages))


def _uv_dependency_names(entries: Any) -> tuple[str, ...]:
    if not isinstance(entries, list):
        return ()
    names = [
        normalise_name("PyPI", str(entry["name"]))
        for entry in entries
        if isinstance(entry, dict) and entry.get("name")
    ]
    return tuple(dict.fromkeys(names))


def _parse_poetry_lock(path: Path) -> LockfileResult:
    """Parse ``poetry.lock``.

    Poetry records each package's own dependencies but not which packages the
    project asked for, so directness cannot be read from this file alone; a
    sibling ``pyproject.toml`` is consulted when present.
    """
    data = _load_toml(path)
    entries = data.get("package", [])
    if not isinstance(entries, list):
        msg = "poetry.lock has no package table"
        raise LockfileError(msg)

    direct, dev_direct, notes = _python_project_dependencies(path.parent)

    packages: list[LockedPackage] = []
    for entry in entries:
        name = entry.get("name")
        version = entry.get("version")
        if not name or not version:
            continue
        normalised = normalise_name("PyPI", str(name))
        # Poetry 1.5+ writes groups here; earlier versions wrote "category".
        groups = entry.get("groups") or ([entry["category"]] if entry.get("category") else [])
        is_dev = bool(groups) and "main" not in groups
        packages.append(
            LockedPackage(
                name=normalised,
                version=str(version),
                ecosystem="PyPI",
                scope=ComponentScope.DEV
                if is_dev or normalised in dev_direct
                else ComponentScope.RUNTIME,
                direct=normalised in direct or normalised in dev_direct,
                dependencies=_poetry_dependency_names(entry.get("dependencies")),
            )
        )
    return LockfileResult(
        path=path,
        kind="poetry.lock",
        ecosystem="PyPI",
        packages=tuple(packages),
        notes=notes,
    )


def _poetry_dependency_names(dependencies: Any) -> tuple[str, ...]:
    if not isinstance(dependencies, Mapping):
        return ()
    return tuple(
        dict.fromkeys(
            normalise_name("PyPI", str(name)) for name in dependencies if str(name) != "python"
        )
    )


def _parse_pdm_lock(path: Path) -> LockfileResult:
    """Parse ``pdm.lock``."""
    data = _load_toml(path)
    entries = data.get("package", [])
    if not isinstance(entries, list):
        msg = "pdm.lock has no package table"
        raise LockfileError(msg)

    direct, dev_direct, notes = _python_project_dependencies(path.parent)

    packages: list[LockedPackage] = []
    for entry in entries:
        name = entry.get("name")
        version = entry.get("version")
        if not name or not version:
            continue
        normalised = normalise_name("PyPI", str(name))
        groups = entry.get("groups", [])
        is_dev = isinstance(groups, list) and bool(groups) and "default" not in groups
        packages.append(
            LockedPackage(
                name=normalised,
                version=str(version),
                ecosystem="PyPI",
                scope=ComponentScope.DEV
                if is_dev or normalised in dev_direct
                else ComponentScope.RUNTIME,
                direct=normalised in direct or normalised in dev_direct,
                # PDM stores requirement strings, so the name is the leading
                # run of characters before any version specifier or bracket.
                dependencies=_requirement_string_names(entry.get("dependencies", [])),
            )
        )
    return LockfileResult(
        path=path, kind="pdm.lock", ecosystem="PyPI", packages=tuple(packages), notes=notes
    )


def _requirement_string_names(entries: Any) -> tuple[str, ...]:
    if not isinstance(entries, list):
        return ()
    names: list[str] = []
    for entry in entries:
        match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(entry))
        if match:
            names.append(normalise_name("PyPI", match.group(1)))
    return tuple(dict.fromkeys(names))


def _parse_pipfile_lock(path: Path) -> LockfileResult:
    """Parse ``Pipfile.lock``.

    Pipenv records resolved versions but no dependency relationships, so the
    inventory is complete while the graph is not. That limitation is reported
    rather than papered over.
    """
    data = _load_json(path)
    if not isinstance(data, dict):
        msg = "Pipfile.lock is not an object"
        raise LockfileError(msg)

    packages: list[LockedPackage] = []
    unpinned: list[str] = []
    for section, scope in (("default", ComponentScope.RUNTIME), ("develop", ComponentScope.DEV)):
        entries = data.get(section, {})
        if not isinstance(entries, dict):
            continue
        for name, entry in entries.items():
            version = entry.get("version") if isinstance(entry, dict) else None
            if not isinstance(version, str) or not version.startswith("=="):
                unpinned.append(str(name))
                continue
            packages.append(
                LockedPackage(
                    name=normalise_name("PyPI", str(name)),
                    version=version.removeprefix("=="),
                    ecosystem="PyPI",
                    scope=scope,
                    # Pipfile.lock lists only what the Pipfile asked for plus
                    # its resolution, flat, with no way to tell them apart.
                    direct=True,
                )
            )

    notes = [
        "Pipfile.lock records no dependency relationships, so the dependency "
        "graph is unavailable and every package is reported as direct."
    ]
    if unpinned:
        notes.append(
            f"{len(unpinned)} entries had no pinned version and were skipped: "
            f"{', '.join(sorted(unpinned)[:5])}"
        )
    return LockfileResult(
        path=path,
        kind="Pipfile.lock",
        ecosystem="PyPI",
        packages=tuple(packages),
        notes=tuple(notes),
    )


def _parse_requirements_txt(path: Path) -> LockfileResult:
    """Parse a fully pinned ``requirements.txt``.

    Unpinned requirements are rejected rather than resolved. Resolving them
    would mean reporting findings about versions that may not be what gets
    installed, which is worse than asking for a lockfile (ADR-0009).
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        msg = f"{path.name} is not readable: {exc}"
        raise LockfileError(msg) from exc

    direct, dev_direct, project_notes = _python_project_dependencies(path.parent)

    packages: list[LockedPackage] = []
    unpinned: list[str] = []
    editable = 0
    for line in _logical_lines(raw):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-e") or stripped.startswith("--editable"):
            editable += 1
            continue
        if stripped.startswith("-"):
            # Other options (--index-url, --hash continuations, -r includes).
            # Includes are not followed: a scan should see one explicit file.
            continue
        match = _REQUIREMENT.match(stripped)
        if match is None:
            unpinned.append(stripped.split(";")[0].strip())
            continue
        normalised = normalise_name("PyPI", match.group("name"))
        packages.append(
            LockedPackage(
                name=normalised,
                version=match.group("version"),
                ecosystem="PyPI",
                scope=ComponentScope.DEV if normalised in dev_direct else ComponentScope.RUNTIME,
                # A flat requirements file gives no graph. When a pyproject
                # names the project's own dependencies, that settles it;
                # otherwise everything is reported as direct.
                direct=(normalised in direct or normalised in dev_direct)
                if (direct or dev_direct)
                else True,
            )
        )

    if unpinned:
        listed = ", ".join(sorted(unpinned)[:5])
        msg = (
            f"{path.name} has {len(unpinned)} unpinned requirement(s): {listed}. "
            "Reachability needs exact versions, so pin them or generate a "
            "lockfile (uv lock, poetry lock, pip-compile)."
        )
        raise LockfileError(msg)

    notes = [
        f"{path.name} records no dependency relationships, so the dependency graph is unavailable."
    ]
    if not (direct or dev_direct):
        notes.append(
            "No pyproject.toml or setup.cfg was found next to it, so direct and "
            "transitive dependencies could not be distinguished."
        )
    notes.extend(project_notes)
    if editable:
        notes.append(f"{editable} editable install(s) were skipped.")

    return LockfileResult(
        path=path,
        kind="requirements.txt",
        ecosystem="PyPI",
        packages=tuple(packages),
        notes=tuple(notes),
    )


def _logical_lines(raw: str) -> Iterable[str]:
    """Join backslash continuations into single logical lines."""
    buffer: list[str] = []
    for line in raw.splitlines():
        if line.rstrip().endswith("\\"):
            buffer.append(line.rstrip()[:-1])
            continue
        buffer.append(line)
        yield "".join(buffer)
        buffer = []
    if buffer:
        yield "".join(buffer)


def _python_project_dependencies(root: Path) -> tuple[set[str], set[str], tuple[str, ...]]:
    """Read a project's own declared dependencies, to identify direct ones.

    Reads ``pyproject.toml`` and ``setup.cfg`` with TOML and INI parsers.
    ``setup.py`` is never executed; a project whose dependencies live only in
    executable code simply yields no directness information.
    """
    direct: set[str] = set()
    dev: set[str] = set()
    notes: list[str] = []

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = _load_toml(pyproject)
        except LockfileError:
            notes.append("pyproject.toml could not be parsed, so directness is approximate.")
            return direct, dev, tuple(notes)
        project = data.get("project", {})
        if isinstance(project, dict):
            direct.update(_requirement_string_names(project.get("dependencies", [])))
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for members in optional.values():
                    direct.update(_requirement_string_names(members))
        groups = data.get("dependency-groups", {})
        if isinstance(groups, dict):
            for members in groups.values():
                dev.update(_requirement_string_names(members))
        poetry = (
            data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
        )
        if isinstance(poetry, dict):
            direct.update(_poetry_dependency_names(poetry.get("dependencies")))
            poetry_groups = poetry.get("group", {})
            if isinstance(poetry_groups, dict):
                for group in poetry_groups.values():
                    if isinstance(group, dict):
                        dev.update(_poetry_dependency_names(group.get("dependencies")))

    setup_cfg = root / "setup.cfg"
    if setup_cfg.is_file() and not direct:
        import configparser

        parser = configparser.ConfigParser()
        try:
            parser.read(setup_cfg, encoding="utf-8")
            raw = parser.get("options", "install_requires", fallback="")
            direct.update(_requirement_string_names(raw.split("\n")))
        except (configparser.Error, OSError):
            notes.append("setup.cfg could not be parsed, so directness is approximate.")

    if (root / "setup.py").is_file() and not direct:
        notes.append(
            "Dependencies appear to be declared in setup.py, which is parsed but "
            "never executed, so directness could not be determined."
        )

    return direct, dev, tuple(notes)


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


def _parse_package_lock_json(path: Path) -> LockfileResult:
    """Parse ``package-lock.json`` version 2 or 3.

    Version 1 is not supported: it stores a nested tree without the flat
    ``packages`` map, and npm has shipped v2 or later since 2020.
    """
    data = _load_json(path)
    if not isinstance(data, dict):
        msg = "package-lock.json is not an object"
        raise LockfileError(msg)

    version = data.get("lockfileVersion")
    entries = data.get("packages")
    if not isinstance(entries, dict):
        msg = (
            f"package-lock.json has lockfileVersion {version!r} and no 'packages' map. "
            "Versions 2 and 3 are supported; run 'npm install' with npm 7 or later "
            "to upgrade the lockfile."
        )
        raise LockfileError(msg)

    root = entries.get("", {})
    direct: set[str] = set()
    dev_direct: set[str] = set()
    if isinstance(root, dict):
        for key in ("dependencies", "optionalDependencies", "peerDependencies"):
            section = root.get(key)
            if isinstance(section, dict):
                direct.update(normalise_name("npm", str(name)) for name in section)
        dev_section = root.get("devDependencies")
        if isinstance(dev_section, dict):
            dev_direct.update(normalise_name("npm", str(name)) for name in dev_section)

    packages: list[LockedPackage] = []
    for key, entry in entries.items():
        if not key or not isinstance(entry, dict):
            continue
        name = entry.get("name") or _npm_name_from_path(key)
        package_version = entry.get("version")
        if not name or not package_version:
            continue
        normalised = normalise_name("npm", str(name))
        if entry.get("dev"):
            scope = ComponentScope.DEV
        elif entry.get("optional"):
            scope = ComponentScope.OPTIONAL
        else:
            scope = ComponentScope.RUNTIME
        dependencies: set[str] = set()
        for section_key in ("dependencies", "optionalDependencies"):
            section = entry.get(section_key)
            if isinstance(section, dict):
                dependencies.update(normalise_name("npm", str(child)) for child in section)
        packages.append(
            LockedPackage(
                name=normalised,
                version=str(package_version),
                ecosystem="npm",
                scope=scope,
                direct=normalised in direct or normalised in dev_direct,
                dependencies=tuple(sorted(dependencies)),
            )
        )

    return LockfileResult(
        path=path,
        kind="package-lock.json",
        ecosystem="npm",
        packages=tuple(packages),
    )


def _npm_name_from_path(key: str) -> str:
    """Return the package name from a ``node_modules`` path key.

    Nested paths such as ``node_modules/a/node_modules/b`` name package ``b``,
    and scoped packages keep their ``@scope/`` prefix.
    """
    _, _, tail = key.rpartition("node_modules/")
    return tail or key


def _parse_pnpm_lock(path: Path) -> LockfileResult:
    """Parse ``pnpm-lock.yaml`` version 6 or 9.

    The two layouts differ: version 6 keeps each package's dependencies beside
    its resolution, version 9 moves them into a ``snapshots`` section. Both are
    handled; anything older is rejected rather than guessed at.
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        msg = f"pnpm-lock.yaml is not readable YAML: {exc}"
        raise LockfileError(msg) from exc
    if not isinstance(data, dict):
        msg = "pnpm-lock.yaml is not a mapping"
        raise LockfileError(msg)

    lockfile_version = str(data.get("lockfileVersion", ""))
    major = lockfile_version.split(".")[0]
    if major not in {"6", "9"}:
        msg = (
            f"pnpm-lock.yaml has lockfileVersion {lockfile_version!r}; "
            "versions 6 and 9 are supported. Re-run 'pnpm install' with a "
            "current pnpm to upgrade it."
        )
        raise LockfileError(msg)

    direct, dev_direct = _pnpm_direct_dependencies(data)
    snapshots = data.get("snapshots") if isinstance(data.get("snapshots"), dict) else {}
    entries = data.get("packages")
    if not isinstance(entries, dict):
        msg = "pnpm-lock.yaml has no packages section"
        raise LockfileError(msg)

    packages: list[LockedPackage] = []
    for key, entry in entries.items():
        name, package_version = _pnpm_split_key(str(key))
        if not name or not package_version:
            continue
        source = entry if isinstance(entry, dict) else {}
        snapshot = snapshots.get(key) if isinstance(snapshots, dict) else None
        dependency_source = snapshot if isinstance(snapshot, dict) else source
        dependencies: set[str] = set()
        for section_key in ("dependencies", "optionalDependencies"):
            section = dependency_source.get(section_key)
            if isinstance(section, dict):
                dependencies.update(normalise_name("npm", str(child)) for child in section)
        normalised = normalise_name("npm", name)
        packages.append(
            LockedPackage(
                name=normalised,
                version=package_version,
                ecosystem="npm",
                scope=ComponentScope.DEV
                if normalised in dev_direct and normalised not in direct
                else ComponentScope.RUNTIME,
                direct=normalised in direct or normalised in dev_direct,
                dependencies=tuple(sorted(dependencies)),
            )
        )

    return LockfileResult(
        path=path, kind="pnpm-lock.yaml", ecosystem="npm", packages=tuple(packages)
    )


def _pnpm_direct_dependencies(data: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    """Return the names a pnpm workspace asks for directly."""
    direct: set[str] = set()
    dev: set[str] = set()
    importers = data.get("importers")
    sources: Sequence[Mapping[str, Any]]
    if isinstance(importers, dict):
        sources = [value for value in importers.values() if isinstance(value, dict)]
    else:
        sources = [data]
    for source in sources:
        for key, target in (
            ("dependencies", direct),
            ("optionalDependencies", direct),
            ("devDependencies", dev),
        ):
            section = source.get(key)
            if isinstance(section, dict):
                target.update(normalise_name("npm", str(name)) for name in section)
    return direct, dev


def _pnpm_split_key(key: str) -> tuple[str, str]:
    """Split a pnpm package key into name and version.

    Keys look like ``/lodash@4.17.21``, ``lodash@4.17.21`` or
    ``/@babel/core@7.23.0(peer@1.0.0)``. The leading slash and the peer suffix
    are both decoration.
    """
    cleaned = _PNPM_PEER_SUFFIX.sub("", key.strip()).lstrip("/")
    name, separator, version = cleaned.rpartition("@")
    if not separator or not name:
        return "", ""
    return name, version


__all__ = [
    "LOCKFILE_PRIORITY",
    "LockedPackage",
    "LockfileError",
    "LockfileResult",
    "find_lockfiles",
    "parse_lockfile",
]
