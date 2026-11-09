"""CycloneDX reading and writing.

The mapping between CycloneDX and our model is written by hand rather than
delegated to a library's object model, because the translation would be needed
either way and doing it directly keeps the output deterministic, which a signed
document requires.

Validation is not written by hand. Documents are checked against the official
CycloneDX JSON schemas, which ship with `cyclonedx-python-lib`, so a document
this project accepts or emits is one the wider ecosystem accepts too.
"""

from __future__ import annotations

import json
from typing import Any

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from sscp_core.enums import ComponentScope, SbomFormat, SbomGenerator, canonical_ecosystem
from sscp_core.models.sbom import Component, DependencyEdge, Sbom
from sscp_core.protocols import Clock, SystemClock
from sscp_core.purl import build_purl, normalise_name, parse_purl
from sscp_core.sbom.generate import serial_number

#: Spec versions this module reads. Writing is always the newest.
READABLE_VERSIONS: dict[str, SchemaVersion] = {
    "1.6": SchemaVersion.V1_6,
    "1.5": SchemaVersion.V1_5,
    "1.4": SchemaVersion.V1_4,
}
WRITE_VERSION = "1.6"

_FORMAT_BY_VERSION: dict[str, SbomFormat] = {
    "1.6": SbomFormat.CYCLONEDX_1_6_JSON,
    "1.5": SbomFormat.CYCLONEDX_1_5_JSON,
    "1.4": SbomFormat.CYCLONEDX_1_4_JSON,
}

#: CycloneDX scope values, which do not line up with ours one to one. It has no
#: notion of a development dependency; that lives in a property instead.
_SCOPE_TO_CDX: dict[ComponentScope, str] = {
    ComponentScope.RUNTIME: "required",
    ComponentScope.OPTIONAL: "optional",
    ComponentScope.DEV: "optional",
}

#: Namespaced properties carrying information CycloneDX has no field for.
PROPERTY_SCOPE = "sscp:scope"
PROPERTY_DIRECT = "sscp:direct"
PROPERTY_NOTE = "sscp:note"


class CycloneDxError(Exception):
    """Raised when a CycloneDX document cannot be read."""


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def to_dict(sbom: Sbom) -> dict[str, Any]:
    """Render an SBOM as a CycloneDX 1.6 document.

    Deterministic: components and dependencies are ordered, and the serial
    number is derived from the inventory's content hash rather than generated
    at random.
    """
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": WRITE_VERSION,
        "serialNumber": serial_number(sbom),
        "version": 1,
        "metadata": {
            "timestamp": sbom.created_at.isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [{"type": "application", "name": "sscp", "version": _tool_version()}]
            },
        },
    }

    if sbom.root_component is not None:
        document["metadata"]["component"] = _component_to_dict(sbom.root_component, root=True)

    if sbom.notes:
        # Limitations of the inventory travel with the document, so a consumer
        # who only has the file still knows what it could not determine.
        document["metadata"]["properties"] = [
            {"name": PROPERTY_NOTE, "value": note} for note in sbom.notes
        ]

    document["components"] = [_component_to_dict(component) for component in sbom.components]
    document["dependencies"] = _dependencies_to_list(sbom)
    return document


def to_json(sbom: Sbom, *, indent: int | None = 2) -> str:
    """Serialise an SBOM as CycloneDX JSON."""
    return json.dumps(to_dict(sbom), indent=indent, sort_keys=False) + "\n"


def _tool_version() -> str:
    from sscp_core import __version__

    return __version__


def _component_to_dict(component: Component, *, root: bool = False) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "bom-ref": component.bom_ref,
        "type": "application" if root else "library",
        "name": component.name,
    }
    if component.version:
        entry["version"] = component.version
    if component.purl:
        entry["purl"] = component.purl
    if not root:
        entry["scope"] = _SCOPE_TO_CDX[component.scope]
    if component.licenses:
        entry["licenses"] = [{"license": {"id": identifier}} for identifier in component.licenses]
    if component.hashes:
        entry["hashes"] = [
            {"alg": file_hash.alg, "content": file_hash.content} for file_hash in component.hashes
        ]
    if not root:
        # CycloneDX has no field for either of these, and both change what a
        # policy decides, so they are carried as namespaced properties.
        entry["properties"] = [
            {"name": PROPERTY_SCOPE, "value": component.scope.value},
            {"name": PROPERTY_DIRECT, "value": "true" if component.direct else "false"},
        ]
    return entry


def _dependencies_to_list(sbom: Sbom) -> list[dict[str, Any]]:
    children: dict[str, set[str]] = {}
    known = {component.bom_ref for component in sbom.components}
    if sbom.root_component is not None:
        known.add(sbom.root_component.bom_ref)
    for edge in sbom.edges:
        if edge.parent_ref in known and edge.child_ref in known:
            children.setdefault(edge.parent_ref, set()).add(edge.child_ref)
    # Every component gets an entry, including leaves: CycloneDX treats a
    # missing entry as "unknown dependencies" and an empty one as "none".
    return [{"ref": ref, "dependsOn": sorted(children.get(ref, set()))} for ref in sorted(known)]


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def from_json(text: str, *, clock: Clock | None = None) -> Sbom:
    """Parse a CycloneDX JSON document.

    Raises:
        CycloneDxError: if the document is not CycloneDX, is a version this
            module does not read, or fails schema validation.
    """
    resolved_clock = clock or SystemClock()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"not valid JSON: {exc}"
        raise CycloneDxError(msg) from exc
    if not isinstance(data, dict):
        msg = "a CycloneDX document must be a JSON object"
        raise CycloneDxError(msg)

    if data.get("bomFormat") != "CycloneDX":
        msg = f"not a CycloneDX document: bomFormat is {data.get('bomFormat')!r}"
        raise CycloneDxError(msg)

    spec_version = str(data.get("specVersion", ""))
    if spec_version not in READABLE_VERSIONS:
        msg = (
            f"CycloneDX {spec_version or 'unknown'} is not supported; "
            f"readable versions are {', '.join(sorted(READABLE_VERSIONS))}"
        )
        raise CycloneDxError(msg)

    validate(text, spec_version=spec_version)
    return _from_dict(data, spec_version=spec_version, clock=resolved_clock)


def validate(text: str, *, spec_version: str | None = None) -> None:
    """Validate a document against the official CycloneDX schema.

    Raises:
        CycloneDxError: with the schema's own message when validation fails.
    """
    if spec_version is None:
        try:
            spec_version = str(json.loads(text).get("specVersion", ""))
        except (json.JSONDecodeError, AttributeError) as exc:
            msg = f"not valid JSON: {exc}"
            raise CycloneDxError(msg) from exc
    schema_version = READABLE_VERSIONS.get(spec_version)
    if schema_version is None:
        msg = f"no schema available for CycloneDX {spec_version!r}"
        raise CycloneDxError(msg)

    problem = JsonStrictValidator(schema_version).validate_str(text)
    if problem is not None:
        msg = f"document does not satisfy the CycloneDX {spec_version} schema: {problem}"
        raise CycloneDxError(msg)


def _from_dict(data: dict[str, Any], *, spec_version: str, clock: Clock) -> Sbom:
    raw_components = data.get("components", [])
    if not isinstance(raw_components, list):
        msg = "'components' must be an array"
        raise CycloneDxError(msg)

    metadata = data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {}
    root_raw = metadata.get("component")
    root_component = (
        _component_from_dict(root_raw, root=True) if isinstance(root_raw, dict) else None
    )

    direct_refs = _direct_refs(data, root_component)

    components: list[Component] = []
    for raw in raw_components:
        if not isinstance(raw, dict):
            continue
        component = _component_from_dict(raw)
        if component is None:
            continue
        if component.bom_ref in direct_refs and not component.direct:
            component = component.model_copy(update={"direct": True})
        components.append(component)

    edges = _edges_from_dict(data)
    notes = tuple(
        str(entry.get("value", ""))
        for entry in metadata.get("properties", [])
        if isinstance(entry, dict) and entry.get("name") == PROPERTY_NOTE
    )

    generator = _generator_from_metadata(metadata)
    sbom = Sbom(
        format=_FORMAT_BY_VERSION[spec_version],
        spec_version=spec_version,
        document_sha256=_document_hash(data),
        generated_by=generator,
        created_at=clock.now(),
        root_component=root_component,
        components=tuple(sorted(components, key=lambda component: component.purl)),
        edges=edges,
        notes=notes,
    )
    return sbom


def _component_from_dict(raw: dict[str, Any], *, root: bool = False) -> Component | None:
    name = raw.get("name")
    if not name:
        return None
    version = str(raw.get("version") or "")
    purl = str(raw.get("purl") or "")

    if purl:
        try:
            parts = parse_purl(purl)
            ecosystem, canonical_name = parts.ecosystem, parts.name
            version = version or (parts.version or "")
            purl = parts.purl
        except ValueError:
            # A malformed purl is recoverable: the name and version are still
            # usable, and dropping the component would understate the
            # inventory, which is the one direction that hides risk.
            ecosystem = _ecosystem_from_group(raw)
            # Normalising here is not cosmetic. Advisory matching joins on the
            # normalised name, so a raw one from a third-party document fails
            # to match with no error anywhere.
            canonical_name = normalise_name(ecosystem, str(name))
            purl = build_purl(ecosystem, canonical_name, version or None)
    else:
        ecosystem = _ecosystem_from_group(raw)
        canonical_name = normalise_name(ecosystem, str(name))
        purl = build_purl(ecosystem, canonical_name, version or None)

    properties = {
        str(entry.get("name")): str(entry.get("value"))
        for entry in raw.get("properties", [])
        if isinstance(entry, dict)
    }
    scope = _scope_from_raw(raw, properties)
    direct = properties.get(PROPERTY_DIRECT) == "true"

    return Component(
        bom_ref=str(raw.get("bom-ref") or purl),
        purl=purl,
        ecosystem=canonical_ecosystem(ecosystem),
        name=canonical_name,
        version=version,
        direct=True if root else direct,
        scope=scope,
        licenses=_licenses_from_raw(raw),
        hashes=tuple(
            {"alg": str(entry.get("alg")), "content": str(entry.get("content"))}
            for entry in raw.get("hashes", [])
            if isinstance(entry, dict) and entry.get("alg") and entry.get("content")
        ),
    )


def _ecosystem_from_group(raw: dict[str, Any]) -> str:
    """Guess an ecosystem for a component with no purl.

    A CycloneDX document is not required to carry purls, and without one the
    ecosystem is genuinely unknown. PyPI is assumed only because this project
    analyses Python; the guess is visible in the component's purl, so a reader
    can see it was made.
    """
    group = raw.get("group")
    if isinstance(group, str) and group.startswith("@"):
        return "npm"
    return "PyPI"


def _scope_from_raw(raw: dict[str, Any], properties: dict[str, str]) -> ComponentScope:
    # Our own property is authoritative when present, because CycloneDX cannot
    # express a development dependency and collapses it to "optional".
    own = properties.get(PROPERTY_SCOPE)
    if own in {scope.value for scope in ComponentScope}:
        return ComponentScope(own)
    cdx_scope = raw.get("scope")
    if cdx_scope == "optional":
        return ComponentScope.OPTIONAL
    if cdx_scope == "excluded":
        return ComponentScope.DEV
    return ComponentScope.RUNTIME


def _licenses_from_raw(raw: dict[str, Any]) -> tuple[str, ...]:
    identifiers: list[str] = []
    for entry in raw.get("licenses", []):
        if not isinstance(entry, dict):
            continue
        license_entry = entry.get("license")
        if isinstance(license_entry, dict):
            identifier = license_entry.get("id") or license_entry.get("name")
            if identifier:
                identifiers.append(str(identifier))
        elif entry.get("expression"):
            identifiers.append(str(entry["expression"]))
    return tuple(dict.fromkeys(identifiers))


def _direct_refs(data: dict[str, Any], root_component: Component | None) -> set[str]:
    """Return the refs the root component depends on directly."""
    if root_component is None:
        return set()
    for entry in data.get("dependencies", []):
        if isinstance(entry, dict) and entry.get("ref") == root_component.bom_ref:
            depends_on = entry.get("dependsOn", [])
            if isinstance(depends_on, list):
                return {str(ref) for ref in depends_on}
    return set()


def _edges_from_dict(data: dict[str, Any]) -> tuple[DependencyEdge, ...]:
    edges: set[tuple[str, str]] = set()
    for entry in data.get("dependencies", []):
        if not isinstance(entry, dict):
            continue
        parent = entry.get("ref")
        depends_on = entry.get("dependsOn", [])
        if not parent or not isinstance(depends_on, list):
            continue
        for child in depends_on:
            edges.add((str(parent), str(child)))
    return tuple(
        DependencyEdge(parent_ref=parent, child_ref=child) for parent, child in sorted(edges)
    )


def _generator_from_metadata(metadata: dict[str, Any]) -> SbomGenerator:
    """Identify what produced an uploaded document, where it says so."""
    tools = metadata.get("tools")
    names: list[str] = []
    if isinstance(tools, dict):
        names = [
            str(entry.get("name", "")).lower()
            for entry in tools.get("components", [])
            if isinstance(entry, dict)
        ]
    elif isinstance(tools, list):
        names = [str(entry.get("name", "")).lower() for entry in tools if isinstance(entry, dict)]
    if any("sscp" in name for name in names):
        return SbomGenerator.SSCP
    if any("syft" in name for name in names):
        return SbomGenerator.SYFT
    return SbomGenerator.UPLOADED


def _document_hash(data: dict[str, Any]) -> str:
    """Hash the inventory of a parsed document, ignoring volatile metadata.

    The timestamp and serial number change on every regeneration, so hashing
    the raw bytes would make two identical inventories look different.
    """
    import hashlib

    payload = {
        "components": sorted(
            [str(entry.get("purl") or entry.get("name")) for entry in data.get("components", [])]
        ),
        "dependencies": sorted(
            [
                [str(entry.get("ref")), sorted(str(ref) for ref in entry.get("dependsOn", []))]
                for entry in data.get("dependencies", [])
                if isinstance(entry, dict)
            ]
        ),
    }
    serialised = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


__all__ = [
    "PROPERTY_DIRECT",
    "PROPERTY_NOTE",
    "PROPERTY_SCOPE",
    "READABLE_VERSIONS",
    "WRITE_VERSION",
    "CycloneDxError",
    "from_json",
    "to_dict",
    "to_json",
    "validate",
]
