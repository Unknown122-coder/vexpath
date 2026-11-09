"""Guard the committed benchmark results.

The benchmark itself clones thirty repositories and downloads every
dependency's source, which is not something a test suite should do. Its output
is committed instead, and this reads it.

What is asserted is the part that can be wrong in a way that matters: a
clearance that broke a soundness precondition. Everything else in the file is
a measurement, and a measurement that moves is information rather than a
failure.

The manifest is checked separately, because a benchmark whose project list has
quietly shrunk stops being the gate it was meant to be.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

MANIFEST = Path(__file__).resolve().parents[3] / "testdata" / "benchmark" / "projects.yaml"
RESULTS = Path(__file__).resolve().parents[3] / "testdata" / "benchmark" / "results.json"

#: The benchmark is specified as thirty real repositories. Fewer would be a
#: quietly weakened gate.
EXPECTED_PROJECTS = 30


def _manifest() -> dict[str, object]:
    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))


def test_the_manifest_names_the_projects_the_gate_requires() -> None:
    projects = _manifest()["projects"]
    assert isinstance(projects, list)
    assert len(projects) == EXPECTED_PROJECTS


def test_every_project_is_pinned_and_described() -> None:
    """A floating ref makes a result depend on when it was run."""
    for project in _manifest()["projects"]:  # type: ignore[union-attr]
        assert project["name"]
        assert project["repo"].startswith("https://github.com/")
        assert project["ref"], f"{project['name']} has no ref"
        # The note says why this project is in the set, which is what stops the
        # list drifting into thirty variations of one shape.
        assert project.get("notes"), f"{project['name']} has no note saying why it is here"


def test_the_project_set_covers_more_than_one_shape() -> None:
    """A benchmark of thirty libraries would not exercise entry points at all."""
    kinds = {project.get("kind") for project in _manifest()["projects"]}  # type: ignore[union-attr]
    assert {"library", "application", "cli"} <= kinds


def test_no_project_appears_twice() -> None:
    names = [project["name"] for project in _manifest()["projects"]]  # type: ignore[union-attr]
    assert len(names) == len(set(names))


# --- The recorded results -------------------------------------------------


def _results() -> dict[str, object]:
    if not RESULTS.is_file():
        pytest.skip(
            "no benchmark results committed yet; run tools/run_benchmark.py --snapshot <dir>"
        )
    return json.loads(RESULTS.read_text(encoding="utf-8"))


def test_no_clearance_broke_a_soundness_precondition() -> None:
    """The one assertion in this file that can catch a real bug.

    Only proven unreachability may clear a finding. The verdict layer enforces
    that and the model validator enforces it again; the benchmark checks it a
    third time from outside, on real data, and anything it finds is a bug in
    both of the first two.
    """
    results = _results()
    problems = [
        problem
        for project in results["projects"]  # type: ignore[union-attr]
        for problem in project["unsound_clearances"]
    ]
    assert problems == []


def test_the_recorded_totals_agree_with_the_projects() -> None:
    """A summary that drifts from its rows is a summary nobody can trust."""
    results = _results()
    projects = [
        project
        for project in results["projects"]  # type: ignore[union-attr]
        if project["status"] == "ok"
    ]
    totals = results["totals"]

    assert totals["scanned"] == len(projects)  # type: ignore[index]
    assert totals["findings"] == sum(project["findings"] for project in projects)  # type: ignore[index]
    assert totals["cleared"] == sum(project["cleared"] for project in projects)  # type: ignore[index]


def test_every_scanned_project_accounts_for_all_its_findings() -> None:
    """Every finding has exactly one verdict, so the parts must sum."""
    for project in _results()["projects"]:  # type: ignore[union-attr]
        if project["status"] != "ok":
            continue
        accounted = (
            project["cleared"]
            + project["under_investigation"]
            + project["reachable"]
            + project["possibly_reachable"]
        )
        assert accounted == project["findings"], project["name"]


def test_a_cleared_finding_implies_a_linked_dependency_graph() -> None:
    """Nothing can be cleared without traversing the dependency's own code.

    Recorded per project rather than per finding, so this is the weaker form of
    the same rule: a project that cleared something must have linked at least
    one dependency graph.
    """
    for project in _results()["projects"]:  # type: ignore[union-attr]
        if project["status"] != "ok" or not project["cleared"]:
            continue
        assert project["linked_packages"] > 0, project["name"]


def test_the_results_record_when_they_were_produced() -> None:
    """A measurement with no date cannot be compared with a later one."""
    assert _results()["generated_at"]
