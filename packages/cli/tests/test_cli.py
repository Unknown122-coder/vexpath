"""The command-line interface."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from sscp.exit_codes import ExitCode
from sscp.main import app

runner = CliRunner()


def test_exit_codes_distinguish_a_vulnerable_build_from_a_broken_scanner() -> None:
    # This is a published contract with CI. A build failing because the code is
    # vulnerable must never look like a build failing because the tool crashed.
    assert ExitCode.OK == 0
    assert ExitCode.POLICY_FAILED == 1
    assert ExitCode.ANALYSIS_ERROR == 2
    assert ExitCode.CONFIG_ERROR == 3
    assert len(set(ExitCode)) == 4


def test_version_reports_capabilities_alongside_versions() -> None:
    result = runner.invoke(app, ["version", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    # A verdict means different things depending on what the build can analyse,
    # so capability is reported with the version, not buried in documentation.
    assert payload["reachability_ecosystems"] == ["PyPI"]
    assert payload["results_schema"] == "sscp.results/1"
    assert payload["cli"]
    assert payload["core"]


def test_version_has_a_human_readable_form() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "reachability for PyPI" in result.stdout


def test_bare_invocation_shows_help_rather_than_doing_something() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.stdout


def test_help_describes_the_product_in_one_sentence() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "reachable" in result.stdout
