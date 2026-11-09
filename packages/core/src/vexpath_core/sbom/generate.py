"""Build a normalised SBOM from a project directory.

Takes the output of a lockfile parser and produces the `Sbom` model the rest of
the pipeline works with. Two things matter here beyond the obvious mapping:

*Determinism.* Components are sorted, and the document's serial number is
derived from its own contents rather than randomly generated. Running a scan
twice on an unchanged project produces byte-identical output, which is what
lets a signed SBOM be compared against a later one.

*Honesty about the graph.* Several lockfile formats record no dependency
relationships. Where that is the case the SBOM carries a note saying so,
because an empty graph and an unrecorded graph look identical otherwise.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
import uuid
from pathlib import Path

from vexpath_core.enums import ComponentScope, SbomFormat, SbomGenerator
from vexpath_core.models.sbom import Component, DependencyEdge, Sbom
from vexpath_core.protocols import Clock, SystemClock
from vexpath_core.purl import build_purl
from vexpath_core.sbom.lockfiles import (
    LockfileError,
    LockfileResult,
    find_lockfiles,
    parse_lockfile,
)

#: Namespace for deriving a document serial number from its contents. A fixed
#: namespace plus a content hash gives a stable URN for identical inventories.
_SERIAL_NAMESPACE = uuid.UUID("6f4c2a1e-9d3b-4c7a-8f21-5b0e7a6d4c93")

#: Runtime beats optional beats dev when the same package appears twice. The
#: strictest scope wins, so a package used at runtime is never filed as a dev
#: dependency and quietly excluded from policy.
_SCOPE_PRECEDENCE: dict[ComponentScope, int] = {
    ComponentScope.RUNTIME: 2,
    ComponentScope.OPTIONAL: 1,
    ComponentScope.DEV: 0,
}


def generate_sbom(
    root: Path,
    *,
    lockfile: Path | None = None,
    clock: Clock | None = None,
) -> Sbom:
    """Generate an SBOM for the project at ``root``.

    Args:
        root: Project directory.
        lockfile: Use this lockfile instead of searching. Useful when a
            repository holds several and the caller knows which one ships.
        clock: Injected so a generated document is reproducible in tests.

    Raises:
        LockfileError: if no supported lockfile is present, or the chosen one
            cannot be used.
    """
    resolved_clock = clock or SystemClock()

    if lockfile is not None:
        chosen = lockfile
    else:
        candidates = find_lockfiles(root)
        if not candidates:
            msg = (
                f"no supported lockfile found in {root}. Expected one of: "
                "uv.lock, poetry.lock, pdm.lock, Pipfile.lock, package-lock.json, "
                "pnpm-lock.yaml, or a fully pinned requirements.txt. For other "
                "ecosystems, generate a CycloneDX document with Syft and pass it "
                "with --sbom."
            )
            raise LockfileError(msg)
        chosen = candidates[0]

    result = parse_lockfile(chosen)
    return sbom_from_lockfile(result, root=root, clock=resolved_clock)


def sbom_from_lockfile(
    result: LockfileResult,
    *,
    root: Path,
    clock: Clock | None = None,
) -> Sbom:
    """Convert a parsed lockfile into a normalised SBOM."""
    resolved_clock = clock or SystemClock()
    merged, dependency_names = _merge_by_purl(result)
    components = tuple(sorted(merged.values(), key=lambda component: component.purl))
    edges, edge_notes = _build_edges(merged, dependency_names)

    notes = list(result.notes)
    notes.extend(edge_notes)
    if not result.has_dependency_graph and not any(
        "dependency relationships" in note for note in notes
    ):
        notes.append(
            f"{result.kind} yielded no dependency relationships, so the dependency "
            "graph is empty rather than absent."
        )

    root_component = _root_component(root)
    document_hash = _content_hash(components, edges, root_component)

    return Sbom(
        format=SbomFormat.CYCLONEDX_1_6_JSON,
        spec_version="1.6",
        document_sha256=document_hash,
        generated_by=SbomGenerator.VEXPATH,
        created_at=resolved_clock.now(),
        root_component=root_component,
        components=components,
        edges=edges,
        notes=tuple(notes),
    )


def _merge_by_purl(
    result: LockfileResult,
) -> tuple[dict[str, Component], dict[str, tuple[str, ...]]]:
    """Collapse duplicate packages into one component each.

    npm legitimately installs the same name and version at several paths, and a
    requirements file can list a package twice. Merging on the purl keeps the
    inventory honest: the strictest scope wins, directness is sticky, and
    dependency names are unioned.

    Returns the components keyed by purl, and each purl's dependency names.
    The second value is returned rather than stored on the component because
    the SBOM model expresses relationships as edges, and rather than held in
    module state because this library is used concurrently.
    """
    merged: dict[str, Component] = {}
    dependencies: dict[str, set[str]] = {}

    for package in result.packages:
        purl = build_purl(package.ecosystem, package.name, package.version)
        existing = merged.get(purl)
        dependencies.setdefault(purl, set()).update(package.dependencies)
        if existing is None:
            merged[purl] = Component(
                bom_ref=purl,
                purl=purl,
                ecosystem=package.ecosystem,
                name=package.name,
                version=package.version,
                direct=package.direct,
                scope=package.scope,
            )
            continue
        merged[purl] = existing.model_copy(
            update={
                "direct": existing.direct or package.direct,
                "scope": _strictest_scope(existing.scope, package.scope),
            }
        )

    dependency_names = {purl: tuple(sorted(names)) for purl, names in dependencies.items()}
    return merged, dependency_names


def _strictest_scope(left: ComponentScope, right: ComponentScope) -> ComponentScope:
    return left if _SCOPE_PRECEDENCE[left] >= _SCOPE_PRECEDENCE[right] else right


def _build_edges(
    merged: dict[str, Component], dependency_names: dict[str, tuple[str, ...]]
) -> tuple[tuple[DependencyEdge, ...], list[str]]:
    """Turn dependency names into edges between components.

    Lockfiles record a dependency by name, not by resolved identity. When two
    versions of the same package are installed, a name therefore matches more
    than one component and the edge set is an over-approximation. That is
    recorded as a note rather than silently resolved to one of them.

    These edges exist to explain why a package is present. Reachability does
    not use them; it uses the import graph of the code itself.
    """
    by_name: dict[str, list[str]] = {}
    for purl, component in merged.items():
        by_name.setdefault(component.name, []).append(purl)

    edges: set[tuple[str, str]] = set()
    ambiguous: set[str] = set()
    for parent_purl in merged:
        for child_name in dependency_names.get(parent_purl, ()):
            targets = by_name.get(child_name, [])
            if len(targets) > 1:
                ambiguous.add(child_name)
            for child_purl in targets:
                if child_purl != parent_purl:
                    edges.add((parent_purl, child_purl))

    root_ref = _ROOT_BOM_REF
    for purl, component in merged.items():
        if component.direct:
            edges.add((root_ref, purl))

    notes: list[str] = []
    if ambiguous:
        listed = ", ".join(sorted(ambiguous)[:5])
        notes.append(
            f"{len(ambiguous)} package name(s) resolve to more than one installed "
            f"version ({listed}), so dependency edges for them include every "
            "candidate. This affects the explanation of why a package is "
            "present, not any verdict."
        )

    ordered = tuple(
        DependencyEdge(parent_ref=parent, child_ref=child) for parent, child in sorted(edges)
    )
    return ordered, notes


#: Reference used for the project itself inside generated documents.
_ROOT_BOM_REF = "root"


def _root_component(root: Path) -> Component:
    """Describe the project being scanned.

    The name comes from package metadata when it is declared, and from the
    directory name otherwise. A version is only reported if it is declared;
    inventing one would put a false claim in a signed document.
    """
    name = root.resolve().name or "unknown"
    version = ""
    ecosystem = "PyPI"

    pyproject = root / "pyproject.toml"
    package_json = root / "package.json"
    if pyproject.is_file():
        try:
            with pyproject.open("rb") as handle:
                data = tomllib.load(handle)
            project = data.get("project", {})
            poetry = data.get("tool", {}).get("poetry", {})
            declared = project if isinstance(project, dict) and project.get("name") else poetry
            if isinstance(declared, dict):
                name = str(declared.get("name") or name)
                version = str(declared.get("version") or "")
        except (OSError, tomllib.TOMLDecodeError):
            # A malformed pyproject is not a reason to abandon the scan; the
            # directory name is a perfectly usable identity.
            pass
    elif package_json.is_file():
        ecosystem = "npm"
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                name = str(data.get("name") or name)
                version = str(data.get("version") or "")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass

    return Component(
        bom_ref=_ROOT_BOM_REF,
        purl=build_purl(ecosystem, name, version or None),
        ecosystem=ecosystem,
        name=name,
        version=version,
        direct=True,
    )


def _content_hash(
    components: tuple[Component, ...],
    edges: tuple[DependencyEdge, ...],
    root_component: Component,
) -> str:
    """Hash the inventory itself, not the serialised document.

    Hashing the content rather than the bytes means the digest does not change
    when only the timestamp does, so two scans of an unchanged project are
    recognisably the same inventory.
    """
    payload = {
        "root": root_component.purl,
        "components": [
            [component.purl, component.scope.value, component.direct] for component in components
        ],
        "edges": [[edge.parent_ref, edge.child_ref] for edge in edges],
    }
    serialised = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


def serial_number(sbom: Sbom) -> str:
    """Return a stable URN serial number for a document.

    Derived from the content hash, so an unchanged inventory keeps the same
    serial number across runs. A random UUID would make every regenerated
    document look like a new one.
    """
    return f"urn:uuid:{uuid.uuid5(_SERIAL_NAMESPACE, sbom.document_sha256)}"


__all__ = ["generate_sbom", "sbom_from_lockfile", "serial_number"]
