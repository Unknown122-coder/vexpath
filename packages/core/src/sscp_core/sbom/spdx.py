"""SPDX 2.3 reading and writing.

SPDX is the other SBOM standard a regulated buyer is likely to send, so it has
to be readable even though CycloneDX is what this project emits by default.

One difference from the CycloneDX module is worth stating plainly: documents
here are checked structurally, against the fields SPDX 2.3 requires, but not
against the official JSON schema. The CycloneDX schemas ship inside a library
this project already depends on, so using them costs nothing; the SPDX schema
does not, and bundling a copy would mean maintaining a second source of truth
for a specification this project does not own. Structural checks catch the
mistakes that matter for analysis, and the limitation is recorded in
``docs/07-standards.md`` rather than hidden.

SPDX expresses a package's identity through an external reference carrying a
package URL. A package without one cannot be matched against advisories, so
that absence is reported as a minimum-element gap rather than passed over.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from typing import Any

from sscp_core.enums import ComponentScope, SbomFormat, SbomGenerator, canonical_ecosystem
from sscp_core.models.sbom import Component, DependencyEdge, Sbom
from sscp_core.protocols import Clock, SystemClock
from sscp_core.purl import build_purl, normalise_name, parse_purl

SUPPORTED_VERSIONS: frozenset[str] = frozenset({"SPDX-2.2", "SPDX-2.3"})
WRITE_VERSION = "SPDX-2.3"

#: Relationship types that mean "this depends on that", in the direction SPDX
#: writes them. SPDX has many relationship types and only these carry a
#: dependency edge for our purposes.
_DEPENDS_FORWARD = frozenset({"DEPENDS_ON", "CONTAINS", "HAS_PREREQUISITE"})
#: And the inverses, which some producers write instead.
_DEPENDS_REVERSE = frozenset({"DEPENDENCY_OF", "CONTAINED_BY", "PREREQUISITE_FOR"})

_SPDXID_UNSAFE = re.compile(r"[^A-Za-z0-9.\-]+")


class SpdxError(Exception):
    """Raised when an SPDX document cannot be read."""


# ---------------------------------------------------------------------------
# Reading: JSON
# ---------------------------------------------------------------------------


def from_json(text: str, *, clock: Clock | None = None) -> Sbom:
    """Parse an SPDX 2.2 or 2.3 JSON document.

    Raises:
        SpdxError: if the document is not SPDX, is an unsupported version, or
            is missing a field SPDX requires.
    """
    resolved_clock = clock or SystemClock()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"not valid JSON: {exc}"
        raise SpdxError(msg) from exc
    if not isinstance(data, dict):
        msg = "an SPDX document must be a JSON object"
        raise SpdxError(msg)

    version = str(data.get("spdxVersion", ""))
    if version not in SUPPORTED_VERSIONS:
        msg = (
            f"SPDX version {version or 'unknown'} is not supported; "
            f"supported versions are {', '.join(sorted(SUPPORTED_VERSIONS))}"
        )
        raise SpdxError(msg)

    _require_fields(data, ("SPDXID", "name", "creationInfo"))

    raw_packages = data.get("packages", [])
    if not isinstance(raw_packages, list):
        msg = "'packages' must be an array"
        raise SpdxError(msg)

    describes = _described_element_ids(data)
    components: dict[str, Component] = {}
    root_component: Component | None = None

    for raw in raw_packages:
        if not isinstance(raw, dict):
            continue
        component = _component_from_package(raw)
        if component is None:
            continue
        if component.bom_ref in describes and root_component is None:
            root_component = component.model_copy(update={"direct": True})
            continue
        components[component.bom_ref] = component

    edges = _edges_from_relationships(data)
    direct_refs = {
        edge.child_ref
        for edge in edges
        if root_component is not None and edge.parent_ref == root_component.bom_ref
    }
    for ref in direct_refs & components.keys():
        components[ref] = components[ref].model_copy(update={"direct": True})

    return Sbom(
        format=SbomFormat.SPDX_2_3_JSON,
        spec_version=version,
        document_sha256=_document_hash(components.values()),
        generated_by=_generator_from_creation_info(data),
        created_at=resolved_clock.now(),
        root_component=root_component,
        components=tuple(sorted(components.values(), key=lambda item: item.purl)),
        edges=edges,
    )


def _require_fields(data: dict[str, Any], names: tuple[str, ...]) -> None:
    missing = [name for name in names if not data.get(name)]
    if missing:
        msg = f"SPDX document is missing required field(s): {', '.join(missing)}"
        raise SpdxError(msg)


def _component_from_package(raw: dict[str, Any]) -> Component | None:
    name = raw.get("name")
    spdx_id = raw.get("SPDXID")
    if not name or not spdx_id:
        return None

    version = str(raw.get("versionInfo") or "")
    purl = _purl_from_external_refs(raw)

    if purl:
        try:
            parts = parse_purl(purl)
            ecosystem, canonical_name = parts.ecosystem, parts.name
            version = version or (parts.version or "")
            purl = parts.purl
        except ValueError:
            ecosystem = "PyPI"
            canonical_name = normalise_name(ecosystem, str(name))
            purl = build_purl(ecosystem, canonical_name, version or None)
    else:
        # Without a package URL this component cannot be matched reliably. It is
        # still carried, so the inventory stays complete and the gap is reported
        # by the minimum-elements check, and its name is normalised so that a
        # match by name at least has a chance of succeeding.
        ecosystem = "PyPI"
        canonical_name = normalise_name(ecosystem, str(name))
        purl = build_purl(ecosystem, canonical_name, version or None)

    return Component(
        bom_ref=str(spdx_id),
        purl=purl,
        ecosystem=canonical_ecosystem(ecosystem),
        name=canonical_name,
        version=version,
        scope=ComponentScope.RUNTIME,
        licenses=_licenses_from_package(raw),
        hashes=tuple(
            {
                "alg": _spdx_algorithm(str(entry["algorithm"])),
                "content": str(entry["checksumValue"]),
            }
            for entry in raw.get("checksums", [])
            if isinstance(entry, dict) and entry.get("algorithm") and entry.get("checksumValue")
        ),
    )


def _purl_from_external_refs(raw: dict[str, Any]) -> str:
    for entry in raw.get("externalRefs", []):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("referenceType", "")).lower() == "purl":
            return str(entry.get("referenceLocator") or "")
    return ""


def _licenses_from_package(raw: dict[str, Any]) -> tuple[str, ...]:
    identifiers = [
        str(raw.get(field))
        for field in ("licenseConcluded", "licenseDeclared")
        if raw.get(field) and str(raw.get(field)) not in {"NOASSERTION", "NONE"}
    ]
    return tuple(dict.fromkeys(identifiers))


def _spdx_algorithm(algorithm: str) -> str:
    """Normalise an SPDX checksum algorithm to the CycloneDX spelling."""
    mapping = {"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA512": "SHA-512", "MD5": "MD5"}
    return mapping.get(algorithm.upper(), algorithm)


def _described_element_ids(data: dict[str, Any]) -> set[str]:
    described: set[str] = set()
    for entry in data.get("documentDescribes", []):
        described.add(str(entry))
    for entry in data.get("relationships", []):
        if isinstance(entry, dict) and entry.get("relationshipType") == "DESCRIBES":
            described.add(str(entry.get("relatedSpdxElement")))
    return described


def _edges_from_relationships(data: dict[str, Any]) -> tuple[DependencyEdge, ...]:
    edges: set[tuple[str, str]] = set()
    for entry in data.get("relationships", []):
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("relationshipType", ""))
        source = entry.get("spdxElementId")
        target = entry.get("relatedSpdxElement")
        if not source or not target:
            continue
        if kind in _DEPENDS_FORWARD:
            edges.add((str(source), str(target)))
        elif kind in _DEPENDS_REVERSE:
            edges.add((str(target), str(source)))
    return tuple(
        DependencyEdge(parent_ref=parent, child_ref=child) for parent, child in sorted(edges)
    )


def _generator_from_creation_info(data: dict[str, Any]) -> SbomGenerator:
    creation_info = data.get("creationInfo", {})
    creators = creation_info.get("creators", []) if isinstance(creation_info, dict) else []
    joined = " ".join(str(entry).lower() for entry in creators)
    if "sscp" in joined:
        return SbomGenerator.SSCP
    if "syft" in joined:
        return SbomGenerator.SYFT
    return SbomGenerator.UPLOADED


def _document_hash(components: Any) -> str:
    payload = sorted(component.purl for component in components)
    serialised = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Reading: tag-value
# ---------------------------------------------------------------------------


def from_tag_value(text: str, *, clock: Clock | None = None) -> Sbom:
    """Parse an SPDX tag-value document.

    Tag-value is line oriented: ``Key: value``, with a ``PackageName`` tag
    starting each package block. It is converted to the same structure the JSON
    reader produces and then handed to it, so both formats cannot drift apart.
    """
    document: dict[str, Any] = {"packages": [], "relationships": []}
    current: dict[str, Any] | None = None

    for key, value in _tag_value_pairs(text):
        if key == "SPDXVersion":
            document["spdxVersion"] = value
        elif key == "DataLicense":
            document["dataLicense"] = value
        elif key == "DocumentName":
            document["name"] = value
        elif key == "DocumentNamespace":
            document["documentNamespace"] = value
        elif key == "Created":
            document.setdefault("creationInfo", {})["created"] = value
        elif key == "Creator":
            document.setdefault("creationInfo", {}).setdefault("creators", []).append(value)
        elif key == "PackageName":
            current = {"name": value}
            document["packages"].append(current)
        elif key == "SPDXID":
            # Before the first PackageName this is the document's own id.
            if current is None:
                document["SPDXID"] = value
            else:
                current["SPDXID"] = value
        elif key == "Relationship":
            # Relationships are document level wherever they appear, and real
            # documents put them both before and after the package blocks.
            _apply_relationship(document, value)
        elif current is not None:
            _apply_package_tag(current, key, value)

    if "spdxVersion" not in document:
        msg = "not an SPDX tag-value document: no SPDXVersion tag"
        raise SpdxError(msg)

    return from_json(json.dumps(document), clock=clock)


def _tag_value_pairs(text: str) -> Iterator[tuple[str, str]]:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, value = stripped.partition(":")
        if not separator:
            continue
        yield key.strip(), value.strip()


def _apply_package_tag(package: dict[str, Any], key: str, value: str) -> None:
    if key == "PackageVersion":
        package["versionInfo"] = value
    elif key == "PackageDownloadLocation":
        package["downloadLocation"] = value
    elif key in {"PackageLicenseConcluded", "PackageLicenseDeclared"}:
        field = "licenseConcluded" if key.endswith("Concluded") else "licenseDeclared"
        package[field] = value
    elif key == "PackageChecksum":
        algorithm, _, checksum = value.partition(":")
        package.setdefault("checksums", []).append(
            {"algorithm": algorithm.strip(), "checksumValue": checksum.strip()}
        )
    elif key == "ExternalRef":
        parts = value.split()
        if len(parts) >= 3:
            category, reference_type, locator = parts[0], parts[1], parts[2]
            package.setdefault("externalRefs", []).append(
                {
                    "referenceCategory": category,
                    "referenceType": reference_type,
                    "referenceLocator": locator,
                }
            )


def _apply_relationship(document: dict[str, Any], value: str) -> None:
    parts = value.split()
    if len(parts) != 3:
        return
    source, kind, target = parts
    entry = {
        "spdxElementId": source,
        "relationshipType": kind,
        "relatedSpdxElement": target,
    }
    if entry not in document["relationships"]:
        document["relationships"].append(entry)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def to_dict(sbom: Sbom) -> dict[str, Any]:
    """Render an SBOM as an SPDX 2.3 document.

    The namespace is derived from the inventory's content hash, so an unchanged
    project produces the same document namespace on every run. SPDX requires
    the namespace to be unique per document; deriving it from content means
    identical inventories are recognisably identical.
    """
    root_id = "SPDXRef-DOCUMENT"
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    if sbom.root_component is not None:
        root_package_id = _spdx_ref(sbom.root_component.bom_ref)
        packages.append(_package_to_dict(sbom.root_component, root_package_id))
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": root_package_id,
            }
        )

    for component in sbom.components:
        packages.append(_package_to_dict(component, _spdx_ref(component.bom_ref)))

    for edge in sbom.edges:
        relationships.append(
            {
                "spdxElementId": _spdx_ref(edge.parent_ref),
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": _spdx_ref(edge.child_ref),
            }
        )

    name = sbom.root_component.name if sbom.root_component else "unknown"
    return {
        "spdxVersion": WRITE_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": root_id,
        "name": name,
        "documentNamespace": f"https://spdx.org/spdxdocs/{name}-{sbom.document_sha256[:32]}",
        "creationInfo": {
            "created": sbom.created_at.isoformat().replace("+00:00", "Z"),
            "creators": [f"Tool: sscp-{_tool_version()}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def to_json(sbom: Sbom, *, indent: int | None = 2) -> str:
    """Serialise an SBOM as SPDX 2.3 JSON."""
    return json.dumps(to_dict(sbom), indent=indent) + "\n"


def _tool_version() -> str:
    from sscp_core import __version__

    return __version__


def _package_to_dict(component: Component, spdx_id: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "SPDXID": spdx_id,
        "name": component.name,
        # SPDX requires this field. NOASSERTION is the correct value when the
        # lockfile does not record a download location, and is honest.
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": component.licenses[0] if component.licenses else "NOASSERTION",
        "licenseDeclared": component.licenses[0] if component.licenses else "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if component.version:
        entry["versionInfo"] = component.version
    if component.purl:
        entry["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": component.purl,
            }
        ]
    if component.hashes:
        entry["checksums"] = [
            {
                "algorithm": file_hash.alg.replace("-", ""),
                "checksumValue": file_hash.content,
            }
            for file_hash in component.hashes
        ]
    return entry


def _spdx_ref(bom_ref: str) -> str:
    """Convert an arbitrary reference into a valid SPDX identifier.

    SPDX identifiers allow only letters, digits, dots and hyphens, which a purl
    is full of other characters. The mapping is deterministic so references
    stay consistent within a document.
    """
    if bom_ref.startswith("SPDXRef-"):
        return bom_ref
    cleaned = _SPDXID_UNSAFE.sub("-", bom_ref).strip("-")
    return f"SPDXRef-{cleaned or 'unnamed'}"


__all__ = [
    "SUPPORTED_VERSIONS",
    "WRITE_VERSION",
    "SpdxError",
    "from_json",
    "from_tag_value",
    "to_dict",
    "to_json",
]
