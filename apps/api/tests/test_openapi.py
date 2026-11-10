"""The committed OpenAPI document.

Committed rather than only served, because a committed document turns an
accidental breaking change into a diff somebody has to look at. Renaming a
field, narrowing a type or dropping an endpoint then shows up in review, where
it is cheap, instead of in a client's CI, where it is not.

Which only works if the file cannot drift, so the first test here is the one
that matters: the file on disk equals what the application would serve. The
rest assert the properties a consumer relies on and that the schema does not
leak anything it should not.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.export_openapi import DESTINATION, document, render


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return document()


def test_the_committed_document_matches_the_application() -> None:
    assert DESTINATION.is_file(), "run: uv run python tools/export_openapi.py"
    on_disk = DESTINATION.read_text(encoding="utf-8")
    # If this fails, the fix is to run the exporter and commit the diff --
    # and then to read that diff, which is the entire point of committing it.
    assert on_disk == render(document()), (
        "apps/api/openapi.json is stale. Run "
        "'uv run python tools/export_openapi.py' and review the diff."
    )


def test_the_document_is_serialised_deterministically() -> None:
    text = DESTINATION.read_text(encoding="utf-8")
    reparsed = json.loads(text)
    # Sorted keys and a trailing newline, so a real change produces a diff of
    # the change rather than of a reordering.
    assert text == json.dumps(reparsed, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def test_it_describes_the_endpoints_a_client_uses(schema: dict[str, Any]) -> None:
    paths = schema["paths"]
    for path in (
        "/v1/me",
        "/v1/projects",
        "/v1/scans",
        "/v1/scans/{scan_id}/findings",
        "/v1/suppressions",
    ):
        assert path in paths, path


def test_the_html_pages_are_not_in_the_schema(schema: dict[str, Any]) -> None:
    # A schema describing pages nobody calls programmatically is noise that
    # makes the part people do call harder to read.
    for path in schema["paths"]:
        assert not path.startswith(("/app", "/login", "/auth/", "/p/", "/badge/", "/package/"))


def test_health_checks_are_described(schema: dict[str, Any]) -> None:
    # They are part of the contract with whatever runs the container.
    assert "/healthz" in schema["paths"]
    assert "/readyz" in schema["paths"]


def test_the_upload_endpoint_names_its_failure_modes(schema: dict[str, Any]) -> None:
    upload = schema["paths"]["/v1/scans"]["post"]
    responses = upload["responses"]
    assert "201" in responses
    # A client has to be able to tell "your document is wrong" from "your
    # project does not exist" without reading prose.
    assert "422" in responses


def test_no_schema_field_is_called_anything_like_a_secret(schema: dict[str, Any]) -> None:
    """The response models must not carry a credential.

    A key's secret exists in one response in its life, from the page that
    created it, and that page is not in this schema. If a field named like a
    secret appears here, something is being returned that should not be.
    """
    forbidden = {"api_key", "key_hash", "secret", "token", "token_hash", "password"}
    components = schema.get("components", {}).get("schemas", {})
    for name, model in components.items():
        for field in model.get("properties", {}):
            assert field not in forbidden, f"{name}.{field}"


def test_the_document_carries_a_version(schema: dict[str, Any]) -> None:
    assert schema["info"]["version"]
    assert schema["openapi"].startswith("3.")


def test_the_exporter_writes_where_the_tests_look() -> None:
    # One constant, so the exporter and the test cannot disagree about where
    # the committed file lives.
    assert Path(__file__).resolve().parents[1] / "openapi.json" == DESTINATION
