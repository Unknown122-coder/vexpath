"""SBOM generation, serialisation and format detection.

Two properties are load-bearing and are tested directly rather than assumed:
output is deterministic, because a signed document that changes on every run
cannot be compared; and the CycloneDX this project emits satisfies the official
schema, because a document the ecosystem rejects is worthless.
"""

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sscp_core.enums import ComponentScope, SbomFormat, SbomGenerator
from sscp_core.protocols import FixedClock
from sscp_core.sbom import (
    UnknownSbomFormatError,
    cyclonedx,
    generate_sbom,
    load,
    minimum_elements,
    spdx,
)
from sscp_core.sbom.cyclonedx import CycloneDxError
from sscp_core.sbom.lockfiles import LockfileError
from sscp_core.sbom.spdx import SpdxError

CLOCK = FixedClock(datetime(2026, 11, 9, 12, 0, tzinfo=UTC))
LATER = FixedClock(datetime(2027, 3, 1, 9, 30, tzinfo=UTC))


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent(
            """
            [project]
            name = "example-service"
            version = "1.4.0"
            dependencies = ["requests>=2.0"]
            """
        ).lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        textwrap.dedent(
            """
            version = 1

            [[package]]
            name = "example-service"
            version = "1.4.0"
            source = { virtual = "." }
            dependencies = [{ name = "requests" }]

            [[package]]
            name = "requests"
            version = "2.31.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [{ name = "urllib3" }]

            [[package]]
            name = "urllib3"
            version = "1.26.17"
            source = { registry = "https://pypi.org/simple" }
            """
        ).lstrip(),
        encoding="utf-8",
    )
    return tmp_path


# --- Generation ------------------------------------------------------------


def test_generation_reads_versions_directness_and_the_graph(project: Path) -> None:
    sbom = generate_sbom(project, clock=CLOCK)
    assert sbom.component_count == 2
    assert sbom.root_component is not None
    assert sbom.root_component.name == "example-service"
    assert sbom.root_component.version == "1.4.0"

    names = {component.name: component for component in sbom.components}
    assert names["requests"].version == "2.31.0"
    assert names["requests"].direct
    assert not names["urllib3"].direct
    # The chain that explains why urllib3 is present.
    assert any(
        edge.parent_ref == names["requests"].bom_ref and edge.child_ref == names["urllib3"].bom_ref
        for edge in sbom.edges
    )


def test_generation_is_deterministic_apart_from_the_timestamp(project: Path) -> None:
    """An unchanged project must produce the same document, or nothing can be
    compared between two scans."""
    first = generate_sbom(project, clock=CLOCK)
    second = generate_sbom(project, clock=LATER)

    assert first.document_sha256 == second.document_sha256
    assert cyclonedx.to_dict(first)["serialNumber"] == cyclonedx.to_dict(second)["serialNumber"]
    assert first.created_at != second.created_at


def test_a_changed_inventory_changes_the_digest(project: Path) -> None:
    before = generate_sbom(project, clock=CLOCK)
    lock = project / "uv.lock"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace('version = "1.26.17"', 'version = "1.26.18"'),
        encoding="utf-8",
    )
    after = generate_sbom(project, clock=CLOCK)
    assert before.document_sha256 != after.document_sha256


def test_a_project_with_no_lockfile_is_told_what_to_do(tmp_path: Path) -> None:
    with pytest.raises(LockfileError) as exc_info:
        generate_sbom(tmp_path)
    message = str(exc_info.value)
    assert "uv.lock" in message
    assert "Syft" in message


def test_duplicate_packages_merge_with_the_strictest_scope(tmp_path: Path) -> None:
    # npm installs the same name and version at several paths; the inventory
    # must not double-count, and a runtime use must not be filed as dev.
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "example",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"lodash": "^4.17.20"}},
                    "node_modules/lodash": {"version": "4.17.20"},
                    "node_modules/a/node_modules/lodash": {"version": "4.17.20", "dev": True},
                },
            }
        ),
        encoding="utf-8",
    )
    sbom = generate_sbom(tmp_path, clock=CLOCK)
    lodash = [c for c in sbom.components if c.name == "lodash"]
    assert len(lodash) == 1
    assert lodash[0].scope is ComponentScope.RUNTIME


# --- CycloneDX -------------------------------------------------------------


def test_emitted_cyclonedx_satisfies_the_official_schema(project: Path) -> None:
    sbom = generate_sbom(project, clock=CLOCK)
    text = cyclonedx.to_json(sbom)
    # Raises if the document is not schema-valid.
    cyclonedx.validate(text)


def test_cyclonedx_round_trips_through_our_own_reader(project: Path) -> None:
    sbom = generate_sbom(project, clock=CLOCK)
    restored = cyclonedx.from_json(cyclonedx.to_json(sbom), clock=CLOCK)

    assert restored.component_count == sbom.component_count
    assert sorted(c.purl for c in restored.components) == sorted(c.purl for c in sbom.components)
    # Scope and directness survive, which CycloneDX alone cannot express.
    original = {c.purl: c for c in sbom.components}
    for component in restored.components:
        assert component.scope is original[component.purl].scope
        assert component.direct == original[component.purl].direct


def test_development_scope_survives_a_round_trip(tmp_path: Path) -> None:
    # CycloneDX has no development scope and collapses it to "optional", so it
    # is carried in a namespaced property instead.
    (tmp_path / "poetry.lock").write_text(
        textwrap.dedent(
            """
            [[package]]
            name = "pytest"
            version = "8.3.3"
            groups = ["dev"]
            """
        ).lstrip(),
        encoding="utf-8",
    )
    sbom = generate_sbom(tmp_path, clock=CLOCK)
    restored = cyclonedx.from_json(cyclonedx.to_json(sbom), clock=CLOCK)
    assert restored.components[0].scope is ComponentScope.DEV


def test_inventory_limitations_travel_with_the_document(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    sbom = generate_sbom(tmp_path, clock=CLOCK)
    assert sbom.notes

    restored = cyclonedx.from_json(cyclonedx.to_json(sbom), clock=CLOCK)
    # A consumer holding only the file still learns what it could not determine.
    assert any("no dependency relationships" in note for note in restored.notes)


def test_a_document_that_is_not_cyclonedx_is_rejected() -> None:
    with pytest.raises(CycloneDxError, match="not a CycloneDX document"):
        cyclonedx.from_json('{"bomFormat": "SomethingElse", "specVersion": "1.6"}')


def test_an_unsupported_spec_version_is_rejected() -> None:
    with pytest.raises(CycloneDxError, match="not supported"):
        cyclonedx.from_json('{"bomFormat": "CycloneDX", "specVersion": "1.2"}')


def test_a_schema_violation_is_reported() -> None:
    # Correct format marker, but a component missing the required 'type', which
    # the official schema rejects.
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"bom-ref": "x", "name": "mystery", "version": "1.0.0"}],
    }
    with pytest.raises(CycloneDxError, match="does not satisfy the CycloneDX"):
        cyclonedx.from_json(json.dumps(document))


def test_a_component_with_a_malformed_purl_is_kept(tmp_path: Path) -> None:
    # Dropping it would understate the inventory, which is the one direction
    # that hides risk.
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-11-09T00:00:00Z"},
        "components": [
            {
                "bom-ref": "broken",
                "type": "library",
                "name": "mystery",
                "version": "1.0.0",
                "purl": "this is not a purl",
            }
        ],
    }
    sbom = cyclonedx.from_json(json.dumps(document), clock=CLOCK)
    assert sbom.component_count == 1
    assert sbom.components[0].name == "mystery"


# --- SPDX ------------------------------------------------------------------


def test_spdx_json_is_read(sboms_dir: Path) -> None:
    sbom = load(sboms_dir / "direct-call.spdx-2.3.json", clock=CLOCK)
    assert sbom.format is SbomFormat.SPDX_2_3_JSON
    names = {component.name for component in sbom.components}
    assert names == {"requests", "urllib3"}
    assert sbom.root_component is not None
    assert sbom.root_component.name == "direct-call"


def test_spdx_depends_on_becomes_an_edge(sboms_dir: Path) -> None:
    sbom = load(sboms_dir / "direct-call.spdx-2.3.json", clock=CLOCK)
    assert sbom.edges
    requests = next(c for c in sbom.components if c.name == "requests")
    assert requests.direct


def test_the_two_fixture_documents_describe_the_same_project(sboms_dir: Path) -> None:
    """Catching format drift: both files are the same inventory."""
    cdx = load(sboms_dir / "direct-call.cdx-1.6.json", clock=CLOCK)
    spdx_document = load(sboms_dir / "direct-call.spdx-2.3.json", clock=CLOCK)

    spdx_purls = {component.purl for component in spdx_document.components}
    cdx_purls = {component.purl for component in cdx.components}
    # The SPDX fixture is a subset by design, so every package it lists must
    # appear in the CycloneDX one with the same purl.
    assert spdx_purls <= cdx_purls


def test_spdx_round_trips(project: Path) -> None:
    sbom = generate_sbom(project, clock=CLOCK)
    restored = spdx.from_json(spdx.to_json(sbom), clock=CLOCK)
    assert restored.component_count == sbom.component_count
    assert {c.purl for c in restored.components} == {c.purl for c in sbom.components}


def test_spdx_tag_value_is_read() -> None:
    text = textwrap.dedent(
        """
        SPDXVersion: SPDX-2.3
        DataLicense: CC0-1.0
        SPDXID: SPDXRef-DOCUMENT
        DocumentName: example
        DocumentNamespace: https://example.invalid/spdx/example
        Creator: Tool: sscp-0.0.1
        Created: 2026-11-09T00:00:00Z

        PackageName: requests
        SPDXID: SPDXRef-Package-requests
        PackageVersion: 2.31.0
        PackageDownloadLocation: NOASSERTION
        ExternalRef: PACKAGE-MANAGER purl pkg:pypi/requests@2.31.0

        Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-requests
        """
    ).lstrip()
    sbom = spdx.from_tag_value(text, clock=CLOCK)
    assert sbom.root_component is not None
    assert sbom.root_component.name == "requests"


def test_an_unsupported_spdx_version_is_rejected() -> None:
    with pytest.raises(SpdxError, match="not supported"):
        spdx.from_json(
            '{"spdxVersion": "SPDX-1.2", "SPDXID": "x", "name": "x", "creationInfo": {}}'
        )


def test_a_missing_required_spdx_field_is_reported() -> None:
    with pytest.raises(SpdxError, match="missing required field"):
        spdx.from_json('{"spdxVersion": "SPDX-2.3", "packages": []}')


# --- Detection and validation ---------------------------------------------


def test_the_format_is_detected_from_content_not_the_filename(
    tmp_path: Path, sboms_dir: Path
) -> None:
    # SBOMs are routinely saved as sbom.json whatever their format.
    disguised = tmp_path / "inventory.txt"
    disguised.write_text(
        (sboms_dir / "direct-call.cdx-1.6.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    assert load(disguised, clock=CLOCK).format is SbomFormat.CYCLONEDX_1_6_JSON


def test_cyclonedx_xml_is_refused_with_a_clear_message(tmp_path: Path) -> None:
    path = tmp_path / "sbom.xml"
    path.write_text('<?xml version="1.0"?><bom/>', encoding="utf-8")
    with pytest.raises(UnknownSbomFormatError, match="CycloneDX XML is not read yet"):
        load(path)


def test_an_unrecognised_file_names_the_supported_formats(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("just some text", encoding="utf-8")
    with pytest.raises(UnknownSbomFormatError, match="CycloneDX JSON"):
        load(path)


def test_an_uploaded_document_is_recognised_as_third_party(sboms_dir: Path) -> None:
    sbom = load(sboms_dir / "mixed-ecosystems.cdx-1.6.json", clock=CLOCK)
    # The fixture names no tool, so it is not attributed to this project.
    assert sbom.generated_by is SbomGenerator.UPLOADED


# --- Minimum elements ------------------------------------------------------


def test_a_generated_document_has_few_gaps(project: Path) -> None:
    gaps = minimum_elements.check(generate_sbom(project, clock=CLOCK))
    # Licences are not in a lockfile, so that gap is expected; nothing else is.
    assert all("licence" in gap for gap in gaps), gaps


def test_a_missing_dependency_graph_is_reported_as_a_gap(tmp_path: Path) -> None:
    (tmp_path / "Pipfile.lock").write_text(
        '{"default": {"requests": {"version": "==2.31.0"}}}', encoding="utf-8"
    )
    gaps = minimum_elements.check(generate_sbom(tmp_path, clock=CLOCK))
    assert any("Dependency relationship" in gap for gap in gaps)


def test_a_component_without_a_version_is_reported_as_a_gap() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-11-09T00:00:00Z"},
        "components": [{"bom-ref": "x", "type": "library", "name": "mystery"}],
    }
    sbom = cyclonedx.from_json(json.dumps(document), clock=CLOCK)
    gaps = minimum_elements.check(sbom)
    assert any("Component version" in gap for gap in gaps)


def test_an_empty_document_is_reported_as_having_nothing_to_attest_to() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-11-09T00:00:00Z"},
        "components": [],
    }
    gaps = minimum_elements.check(cyclonedx.from_json(json.dumps(document), clock=CLOCK))
    assert any("nothing to attest to" in gap for gap in gaps)
