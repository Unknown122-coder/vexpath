"""Consistency of the fixture repositories.

The reachability benchmark (M2) is only as trustworthy as these fixtures. These
tests check the fixtures themselves: that every expectation names an advisory
that exists in the frozen snapshot, that the declared verdicts are internally
consistent, and that between them they cover every verdict rule in
``docs/03-reachability-design.md`` section 5.

Catching a malformed fixture here is much cheaper than debugging a benchmark
failure caused by the fixture rather than the analyser.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from vexpath_core.enums import ReachStatus, Verdict, VexJustification
from vexpath_core.purl import parse_purl
from vexpath_core.snapshot import read_snapshot

EXPECTED_FIXTURES = {
    "direct-call",
    "method-chain",
    "subclass-override",
    "dynamic-dispatch",
    "unused-transitive",
    "module-level",
}


def _load(directory: Path) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load((directory / "expected.yaml").read_text("utf-8"))
    return data


def _fixtures(root: Path) -> list[tuple[str, dict[str, Any]]]:
    return [(d.name, _load(d)) for d in sorted(root.iterdir()) if d.is_dir()]


def test_all_six_fixtures_are_present(fixture_repos_dir: Path) -> None:
    assert {d.name for d in fixture_repos_dir.iterdir() if d.is_dir()} == EXPECTED_FIXTURES


def test_every_fixture_has_sources_and_a_pinned_lockfile(fixture_repos_dir: Path) -> None:
    for name, spec in _fixtures(fixture_repos_dir):
        directory = fixture_repos_dir / name
        assert (directory / spec["lockfile"]).is_file(), name
        assert list(directory.rglob("*.py")), name
        requirements = (directory / spec["lockfile"]).read_text("utf-8")
        pins = [
            line
            for line in requirements.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert pins, name
        # Unpinned requirements cannot support reachability (ADR-0009), so the
        # fixtures must not contain any.
        assert all("==" in line for line in pins), name


def test_every_expectation_names_an_advisory_in_the_snapshot(
    fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    _, advisories = read_snapshot(snapshot_dir)
    known = {advisory.id for advisory in advisories}
    for name, spec in _fixtures(fixture_repos_dir):
        for expectation in spec["expected"]:
            assert expectation["advisory"] in known, f"{name}: {expectation['advisory']}"


def test_every_expectation_names_a_version_the_advisory_affects(
    fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    _, advisories = read_snapshot(snapshot_dir)
    by_id = {advisory.id: advisory for advisory in advisories}
    for name, spec in _fixtures(fixture_repos_dir):
        for expectation in spec["expected"]:
            component = parse_purl(expectation["component"])
            advisory = by_id[expectation["advisory"]]
            affected_names = {package.name for package in advisory.affected}
            assert component.name in affected_names, f"{name}: {component.name}"


def test_expected_verdicts_are_internally_consistent(fixture_repos_dir: Path) -> None:
    for name, spec in _fixtures(fixture_repos_dir):
        for expectation in spec["expected"]:
            verdict = Verdict(expectation["verdict"])
            status = ReachStatus(expectation["reach_status"])

            if verdict is Verdict.NOT_AFFECTED:
                # The product's central promise, checked against the fixtures
                # themselves so no fixture can encode a forbidden conclusion.
                assert status.may_suppress, f"{name} clears a finding from {status.value}"
                assert VexJustification(expectation["justification"])
                assert "must_search_symbols" in expectation, name
            else:
                assert "justification" not in expectation, name

            if verdict is Verdict.AFFECTED:
                assert status.is_reachable, name
                assert expectation["must_include_symbols"], name

            if status is ReachStatus.REACHABLE_POSSIBLE:
                assert expectation.get("via_dynamic_edges") is True, name
                assert expectation["confidence"] == "low", name


def test_the_fixtures_cover_every_outcome_that_matters(fixture_repos_dir: Path) -> None:
    statuses = {
        ReachStatus(expectation["reach_status"])
        for _, spec in _fixtures(fixture_repos_dir)
        for expectation in spec["expected"]
    }
    assert ReachStatus.REACHABLE_CONFIRMED in statuses
    assert ReachStatus.REACHABLE_POSSIBLE in statuses
    assert ReachStatus.UNREACHABLE in statuses


def test_a_vendored_dependency_is_present_where_one_is_declared(
    fixture_repos_dir: Path,
) -> None:
    # A fixture that tests dynamic dispatch needs a dependency whose shape is
    # fixed forever, so it is vendored rather than fetched.
    for name, spec in _fixtures(fixture_repos_dir):
        for vendored in spec.get("vendored_packages", []):
            package = fixture_repos_dir / name / vendored
            assert (package / "__init__.py").is_file(), f"{name}: {vendored}"


@pytest.mark.parametrize("fixture", sorted(EXPECTED_FIXTURES))
def test_every_fixture_source_file_parses(fixture: str, fixture_repos_dir: Path) -> None:
    import ast

    for source in (fixture_repos_dir / fixture).rglob("*.py"):
        # The analyser parses these with ast; a fixture it cannot parse would
        # fail the benchmark for the wrong reason.
        ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
