"""The command-line interface.

The exit code and the shape of machine-readable output are a contract with CI,
so both are tested directly. So is the separation of streams: a command whose
JSON is polluted by a progress message breaks every pipeline that consumes it.
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
def env(snapshot_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the CLI at the frozen snapshot, so tests are offline."""
    monkeypatch.setenv("VEXPATH_ADVISORY_SNAPSHOT_DIR", str(snapshot_dir))


# --- Contract --------------------------------------------------------------


def test_exit_codes_distinguish_a_vulnerable_build_from_a_broken_scanner() -> None:
    # A build failing because the code is vulnerable must never look like a
    # build failing because the tool crashed.
    assert ExitCode.OK == 0
    assert ExitCode.POLICY_FAILED == 1
    assert ExitCode.ANALYSIS_ERROR == 2
    assert ExitCode.CONFIG_ERROR == 3
    assert len(set(ExitCode)) == 4


def test_version_reports_capabilities_alongside_versions() -> None:
    result = runner.invoke(app, ["version", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["reachability_ecosystems"] == ["PyPI"]
    assert payload["results_schema"] == "vexpath.results/1"
    # The build states that reachability is unavailable rather than letting a
    # reader assume a verdict was reachability-informed.
    assert payload["reachability_available"] is False


def test_version_lists_the_lockfiles_it_understands() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "uv.lock" in result.stdout
    assert "not available in this build" in result.stdout


def test_bare_invocation_shows_help_rather_than_doing_something() -> None:
    assert "Usage" in runner.invoke(app, []).stdout


def test_help_describes_the_product_in_one_sentence() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "reachable" in result.stdout


# --- sbom ------------------------------------------------------------------


def test_sbom_generate_writes_a_valid_document(fixture_repos_dir: Path) -> None:
    result = runner.invoke(app, ["sbom", "generate", str(fixture_repos_dir / "direct-call")])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert any(c["name"] == "requests" for c in document["components"])


def test_sbom_generate_output_is_clean_json(fixture_repos_dir: Path) -> None:
    """Progress notes go to stderr, so redirecting stdout yields valid JSON."""
    result = runner.invoke(app, ["sbom", "generate", str(fixture_repos_dir / "direct-call")])
    # Would raise if a note had been written to stdout.
    json.loads(result.stdout)


def test_sbom_generate_can_write_spdx(fixture_repos_dir: Path, tmp_path: Path) -> None:
    output = tmp_path / "sbom.spdx.json"
    result = runner.invoke(
        app,
        [
            "sbom",
            "generate",
            str(fixture_repos_dir / "direct-call"),
            "--format",
            "spdx",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["spdxVersion"] == "SPDX-2.3"


def test_sbom_generate_without_a_lockfile_fails_as_an_analysis_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["sbom", "generate", str(tmp_path)])
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)


def test_sbom_validate_reports_gaps_without_failing(sboms_dir: Path) -> None:
    result = runner.invoke(app, ["sbom", "validate", str(sboms_dir / "direct-call.cdx-1.6.json")])
    # An incomplete document is still analysable; whether the gaps matter is
    # the reader's call.
    assert result.exit_code == 0
    assert "is a valid cyclonedx-1.6-json document" in result.stdout


def test_sbom_validate_json_output_is_machine_readable(sboms_dir: Path) -> None:
    result = runner.invoke(
        app,
        ["sbom", "validate", str(sboms_dir / "direct-call.spdx-2.3.json"), "--format", "json"],
    )
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["format"] == "spdx-2.3-json"


def test_sbom_validate_rejects_a_non_sbom(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("not an sbom", encoding="utf-8")
    result = runner.invoke(app, ["sbom", "validate", str(path)])
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)


def test_sbom_lockfiles_lists_what_a_scan_would_use(fixture_repos_dir: Path) -> None:
    result = runner.invoke(app, ["sbom", "lockfiles", str(fixture_repos_dir / "direct-call")])
    assert result.exit_code == 0
    assert "requirements.txt" in result.stdout
    assert "would be used" in result.stdout


def test_sbom_lockfiles_without_one_is_a_configuration_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["sbom", "lockfiles", str(tmp_path)])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)


# --- scan ------------------------------------------------------------------


def test_scan_reports_the_expected_finding(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call")])
    assert result.exit_code == 0
    assert "CVE-2024-35195" in result.stdout
    assert "requests 2.31.0 -> 2.32.0" in result.stdout


def test_scan_succeeds_by_default_even_with_findings(env: None, fixture_repos_dir: Path) -> None:
    # Until policy evaluation lands, failing the build is opt-in rather than
    # a surprise.
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call")])
    assert result.exit_code == 0


def test_scan_can_be_asked_to_fail_on_findings(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--fail-on-findings"]
    )
    assert result.exit_code == int(ExitCode.POLICY_FAILED)


def test_scan_exits_cleanly_when_nothing_is_found(env: None, tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on-findings"])
    assert result.exit_code == 0
    assert "No advisories match" in result.stdout


def test_scan_json_output_matches_the_results_schema(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--format", "json"]
    )
    payload = json.loads(result.stdout)
    assert payload["schema"] == "vexpath.results/1"
    assert payload["advisory_snapshot_id"] == "test-snapshot-0001"
    assert payload["findings"][0]["advisory"]["id"] == "CVE-2024-35195"


def test_scan_sarif_output_is_well_formed(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--format", "sarif"]
    )
    document = json.loads(result.stdout)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "CVE-2024-35195"


def test_scan_markdown_output_is_a_comment(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--format", "markdown"]
    )
    assert result.stdout.startswith("## Supply-chain scan")


def test_scan_says_reachability_is_unavailable(env: None, fixture_repos_dir: Path) -> None:
    # Letting someone believe a verdict was reachability-informed when it was
    # not is the failure this message prevents.
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call")])
    assert "Reachability analysis is not available" in result.stderr


def test_scan_names_the_snapshot_it_used(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call")])
    assert "test-snapshot-0001" in result.stderr


def test_scan_warns_when_it_has_no_snapshot(
    fixture_repos_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("VEXPATH_ADVISORY_SNAPSHOT_DIR", raising=False)
    # Point the live source at a port nothing listens on, so the command fails
    # fast rather than reaching the internet.
    monkeypatch.setenv("VEXPATH_OSV_API_BASE", "http://127.0.0.1:1")
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call")])
    assert "will not be reproducible" in result.stderr
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)
    assert "vexpath advisory sync" in result.stderr


def test_scan_can_analyse_a_supplied_sbom(env: None, sboms_dir: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--sbom", str(sboms_dir / "direct-call.cdx-1.6.json")],
    )
    assert result.exit_code == 0
    assert "urllib3" in result.stdout


def test_scan_rejects_an_unreadable_snapshot(fixture_repos_dir: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--snapshot", str(tmp_path)]
    )
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)
    assert "snapshot.json is missing" in result.stderr


# --- advisory --------------------------------------------------------------


def test_advisory_show_describes_an_advisory(env: None) -> None:
    result = runner.invoke(app, ["advisory", "show", "CVE-2024-35195"])
    assert result.exit_code == 0
    assert "requests" in result.stdout
    assert "fixed in: 2.32.0" in result.stdout
    assert "Vulnerable symbols" in result.stdout


def test_advisory_show_resolves_an_alias(env: None) -> None:
    # A lookup by any known identifier must work; users paste whichever one
    # their scanner showed them.
    result = runner.invoke(app, ["advisory", "show", "GHSA-9wx4-h78v-vm56"])
    assert result.exit_code == 0
    assert "CVE-2024-35195" in result.stdout


def test_advisory_show_explains_missing_symbols(env: None) -> None:
    result = runner.invoke(app, ["advisory", "show", "CVE-2024-FIXTURE-NOSYMBOLS"])
    assert result.exit_code == 0
    assert "No vulnerable symbols" in result.stdout
    assert "under investigation" in result.stdout


def test_advisory_show_marks_a_withdrawn_advisory(env: None) -> None:
    result = runner.invoke(app, ["advisory", "show", "CVE-2024-FIXTURE-WITHDRAWN"])
    assert "produces no findings" in result.stdout


def test_advisory_show_json_is_the_full_record(env: None) -> None:
    result = runner.invoke(app, ["advisory", "show", "CVE-2024-35195", "--format", "json"])
    payload = json.loads(result.stdout)
    assert payload["id"] == "CVE-2024-35195"
    assert payload["affected"][0]["name"] == "requests"


def test_advisory_show_fails_clearly_for_an_unknown_identifier(env: None) -> None:
    result = runner.invoke(app, ["advisory", "show", "CVE-1999-0001"])
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)
    assert "is not in the snapshot" in result.stderr


def test_advisory_coverage_reports_both_numbers(env: None) -> None:
    result = runner.invoke(app, ["advisory", "coverage"])
    assert result.exit_code == 0
    assert "PyPI" in result.stdout
    # Symbol coverage and fix-reference coverage mean different things, and the
    # report has to distinguish them or it misleads.
    assert "SYMBOLS" in result.stdout
    assert "FIX" in result.stdout
    assert "ANALYSABLE" in result.stdout
    assert "How a fix commit would be recovered" in result.stdout


def test_advisory_coverage_explains_what_it_excludes(env: None) -> None:
    result = runner.invoke(app, ["advisory", "coverage"])
    assert "malicious-package records" in result.stdout
    assert "withdrawn" in result.stdout


def test_advisory_coverage_json_is_machine_readable(env: None) -> None:
    result = runner.invoke(app, ["advisory", "coverage", "--format", "json"])
    payload = json.loads(result.stdout)
    assert payload["snapshot"] == "test-snapshot-0001"
    by_ecosystem = {row["ecosystem"]: row for row in payload["ecosystems"]}
    assert by_ecosystem["PyPI"]["with_symbols"] == 5


def test_advisory_commands_need_a_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VEXPATH_ADVISORY_SNAPSHOT_DIR", raising=False)
    result = runner.invoke(app, ["advisory", "coverage"])
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)
    assert "no snapshot given" in result.stderr
