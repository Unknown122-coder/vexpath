"""``vexpath report``: one scan, rendered three ways, with nothing re-analysed.

The property worth testing is that it *is* the same scan. Re-running the
analysis to get SARIF instead of a table is not only slow, it is wrong: a
second run against a corpus that has moved on reaches different verdicts, so
the SARIF a pipeline uploads would not match the table a developer read. These
tests assert the renderings agree, and that the document is validated rather
than trusted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vexpath.exit_codes import ExitCode
from vexpath.main import app

runner = CliRunner()


@pytest.fixture
def results(tmp_path: Path, fixture_repos_dir: Path, snapshot_dir: Path) -> Path:
    """A real scan result, produced by the real command.

    Scanned once, here, and re-rendered by every test below -- which is the
    behaviour under test, not a shortcut.
    """
    scanned = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--format", "json", "--no-reach"],
        env={"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)},
    )
    assert scanned.exit_code == 0, scanned.output
    path = tmp_path / "results.json"
    path.write_text(scanned.stdout, encoding="utf-8")
    return path


def test_the_table_is_the_same_as_the_scan_printed(
    results: Path, fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    rendered = runner.invoke(app, ["report", str(results)])
    assert rendered.exit_code == 0, rendered.output

    directly = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach"],
        env={"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)},
    )
    # The same renderer over the same document, so the only way these differ
    # is if one of them re-analysed something.
    assert rendered.stdout == directly.stdout


def test_sarif_is_well_formed_and_anchored_to_the_lockfile(results: Path) -> None:
    rendered = runner.invoke(app, ["report", str(results), "--format", "sarif"])
    assert rendered.exit_code == 0, rendered.output
    document = json.loads(rendered.stdout)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["tool"]["driver"]["name"]

    locations = [
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in document["runs"][0]["results"]
    ]
    # A dependency finding has no line of source code, so every alert is
    # anchored to the file that put the component there. "unknown" would make
    # code scanning show them all against nothing.
    assert locations
    assert all(
        location.endswith(("uv.lock", "poetry.lock", "requirements.txt")) for location in locations
    ), locations


def test_the_lockfile_comes_from_the_document(results: Path) -> None:
    document = json.loads(results.read_text(encoding="utf-8"))
    # Recorded by the scan, so a report rendered in another job -- or months
    # later -- anchors to the same file the scan read.
    assert document["project"]["lockfile"]


def test_the_lockfile_can_be_overridden(results: Path) -> None:
    rendered = runner.invoke(
        app, ["report", str(results), "--format", "sarif", "--lockfile", "deps/locked.txt"]
    )
    document = json.loads(rendered.stdout)
    uri = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    # For a document written by an older build, which recorded nothing.
    assert uri == "deps/locked.txt"


def test_markdown_is_rendered(results: Path) -> None:
    rendered = runner.invoke(app, ["report", str(results), "--format", "markdown"])
    assert rendered.exit_code == 0
    assert rendered.stdout.lstrip().startswith("#")


def test_json_round_trips_through_the_model(results: Path) -> None:
    rendered = runner.invoke(app, ["report", str(results), "--format", "json"])
    assert rendered.exit_code == 0
    # Re-serialised through the model rather than copied byte for byte, so a
    # document that comes back out is one this build genuinely understood.
    assert (
        json.loads(rendered.stdout)["schema"]
        == json.loads(results.read_text(encoding="utf-8"))["schema"]
    )


def test_output_can_go_to_a_file_and_the_note_does_not_pollute_it(
    results: Path, tmp_path: Path
) -> None:
    destination = tmp_path / "out.sarif"
    rendered = runner.invoke(
        app, ["report", str(results), "--format", "sarif", "-o", str(destination)]
    )
    assert rendered.exit_code == 0
    # Valid JSON in the file, and the "wrote …" line on standard error, so a
    # caller redirecting standard output does not find prose in their SARIF.
    assert json.loads(destination.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert destination.name not in rendered.stdout


def test_a_document_that_is_not_a_scan_result_is_refused(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text('{"schema": "vexpath.results/1"}', encoding="utf-8")
    rendered = runner.invoke(app, ["report", str(broken)])
    # Validated through the same model the analysis produced: a hand-edited
    # file must not render into a report that looks authoritative.
    assert rendered.exit_code == int(ExitCode.ANALYSIS_ERROR)
    assert "not a vexpath scan result" in rendered.output


def test_a_file_that_is_not_json_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("looked fine to me", encoding="utf-8")
    assert runner.invoke(app, ["report", str(path)]).exit_code == int(ExitCode.ANALYSIS_ERROR)


def test_a_missing_file_is_refused_before_anything_else(tmp_path: Path) -> None:
    rendered = runner.invoke(app, ["report", str(tmp_path / "nope.json")])
    assert rendered.exit_code != 0


def test_cleared_findings_can_be_shown(results: Path) -> None:
    # The same flag the scan has, because the point of the clearances is that
    # somebody can check them.
    assert runner.invoke(app, ["report", str(results), "--show-cleared"]).exit_code == 0
