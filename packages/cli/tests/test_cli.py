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

#: Written out rather than escaped inline, so generated metadata files are
#: readable in this source.
NEWLINE = chr(10)


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
    # A reader of a report has to know what this build can analyse, because a
    # cleared finding means nothing unless reachability actually ran.
    assert payload["reachability_available"] is True


def test_version_lists_the_lockfiles_it_understands() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "uv.lock" in result.stdout
    # Reachability covers fewer ecosystems than matching does, and the table
    # says which rather than implying it covers everything.
    assert "reachability    PyPI" in result.stdout
    assert "every ecosystem OSV publishes" in result.stdout


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
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach"])
    assert result.exit_code == 0
    assert "CVE-2024-35195" in result.stdout
    assert "requests 2.31.0 -> 2.32.0" in result.stdout


def test_scan_succeeds_by_default_even_with_findings(env: None, fixture_repos_dir: Path) -> None:
    # Until policy evaluation lands, failing the build is opt-in rather than
    # a surprise.
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach"])
    assert result.exit_code == 0


def test_scan_can_be_asked_to_fail_on_findings(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--fail-on-findings", "--no-reach"]
    )
    assert result.exit_code == int(ExitCode.POLICY_FAILED)


def test_scan_exits_cleanly_when_nothing_is_found(env: None, tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on-findings", "--no-reach"])
    assert result.exit_code == 0
    assert "No advisories match" in result.stdout


def test_scan_json_output_matches_the_results_schema(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--format", "json", "--no-reach"]
    )
    payload = json.loads(result.stdout)
    assert payload["schema"] == "vexpath.results/1"
    assert payload["advisory_snapshot_id"] == "test-snapshot-0001"
    assert payload["findings"][0]["advisory"]["id"] == "CVE-2024-35195"


def test_scan_sarif_output_is_well_formed(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--format", "sarif", "--no-reach"]
    )
    document = json.loads(result.stdout)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "CVE-2024-35195"


def test_scan_markdown_output_is_a_comment(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--format", "markdown", "--no-reach"]
    )
    assert result.stdout.startswith("## Supply-chain scan")


def test_scan_says_when_reachability_is_turned_off(env: None, fixture_repos_dir: Path) -> None:
    # Letting someone believe a verdict was reachability-informed when it was
    # not is the failure this message prevents.
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach"])
    assert "Reachability analysis is off" in result.stderr
    assert "No finding will be cleared" in result.stderr
    assert "not run" in result.stdout


def test_scan_clears_a_finding_when_given_the_environment(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    """The flag that makes the report short, exercised through the real command."""
    import shutil

    site_packages = tmp_path / "env" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    vendor = fixture_repos_dir / "unused-transitive" / "vendor"
    for distribution, version, import_name in (
        ("requests", "2.31.0", "requests"),
        ("urllib3", "1.26.17", "urllib3"),
    ):
        shutil.copytree(vendor / import_name, site_packages / import_name)
        info = site_packages / f"{distribution}-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(
            f"Name: {distribution}\nVersion: {version}\n", encoding="utf-8"
        )
        (info / "top_level.txt").write_text(f"{import_name}\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture_repos_dir / "unused-transitive"),
            "--environment",
            str(tmp_path / "env"),
            "--no-cache",
        ],
    )
    assert result.exit_code == 0
    assert "2 not affected" in result.stdout
    # Cleared findings are out of the way by default, and named on request.
    assert "CVE-2023-45803" not in result.stdout

    shown = runner.invoke(
        app,
        [
            "scan",
            str(fixture_repos_dir / "unused-transitive"),
            "--environment",
            str(tmp_path / "env"),
            "--no-cache",
            "--show-cleared",
        ],
    )
    assert "CVE-2023-45803" in shown.stdout


def test_scan_names_the_snapshot_it_used(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach"])
    assert "test-snapshot-0001" in result.stderr


def test_scan_warns_when_it_has_no_snapshot(
    fixture_repos_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("VEXPATH_ADVISORY_SNAPSHOT_DIR", raising=False)
    # Point the live source at a port nothing listens on, so the command fails
    # fast rather than reaching the internet.
    monkeypatch.setenv("VEXPATH_OSV_API_BASE", "http://127.0.0.1:1")
    result = runner.invoke(app, ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach"])
    assert "will not be reproducible" in result.stderr
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)
    assert "vexpath advisory sync" in result.stderr


def test_scan_can_analyse_a_supplied_sbom(env: None, sboms_dir: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--sbom",
            str(sboms_dir / "direct-call.cdx-1.6.json"),
            "--no-reach",
        ],
    )
    assert result.exit_code == 0
    assert "urllib3" in result.stdout


# --- reach -----------------------------------------------------------------


def _synthetic_environment(fixture_repos_dir: Path, tmp_path: Path, fixture: str) -> Path:
    """Lay out the fixture's vendored dependencies as an installed environment."""
    import shutil

    site_packages = tmp_path / "env" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    vendor = fixture_repos_dir / fixture / "vendor"
    for distribution, version, import_name in (
        ("requests", "2.31.0", "requests"),
        ("urllib3", "1.26.17", "urllib3"),
    ):
        source = vendor / import_name
        if not source.is_dir():
            continue
        shutil.copytree(source, site_packages / import_name)
        info = site_packages / f"{distribution}-{version}.dist-info"
        info.mkdir(exist_ok=True)
        (info / "METADATA").write_text(
            f"Name: {distribution}" + NEWLINE + f"Version: {version}" + NEWLINE,
            encoding="utf-8",
        )
        (info / "top_level.txt").write_text(import_name + NEWLINE, encoding="utf-8")
    return tmp_path / "env"


def test_reach_explains_a_reachable_advisory(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    environment = _synthetic_environment(fixture_repos_dir, tmp_path, "direct-call")
    result = runner.invoke(
        app,
        [
            "reach",
            str(fixture_repos_dir / "direct-call"),
            "--advisory",
            "CVE-2024-35195",
            "--environment",
            str(environment),
            "--no-cache",
        ],
    )
    # A reachable verdict is the actionable one, so it is distinguishable
    # without parsing the output.
    assert result.exit_code == int(ExitCode.POLICY_FAILED)
    assert "reachable_confirmed" in result.stdout
    assert "requests.sessions.Session.send" in result.stdout
    assert "Entry points" in result.stdout
    assert "Graph the answer rests on" in result.stdout


def test_reach_explains_a_cleared_advisory_and_exits_zero(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    environment = _synthetic_environment(fixture_repos_dir, tmp_path, "unused-transitive")
    result = runner.invoke(
        app,
        [
            "reach",
            str(fixture_repos_dir / "unused-transitive"),
            "--advisory",
            "CVE-2023-45803",
            "--environment",
            str(environment),
            "--no-cache",
        ],
    )
    assert result.exit_code == 0
    assert "not_affected" in result.stdout
    assert "unreachable" in result.stdout
    assert "No path from" in result.stdout


def test_reach_json_output_carries_the_evidence(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    environment = _synthetic_environment(fixture_repos_dir, tmp_path, "direct-call")
    result = runner.invoke(
        app,
        [
            "reach",
            str(fixture_repos_dir / "direct-call"),
            "--advisory",
            "CVE-2024-35195",
            "--environment",
            str(environment),
            "--no-cache",
            "--format",
            "json",
        ],
    )
    payload = json.loads(result.stdout)
    assert payload["advisory"]["id"] == "CVE-2024-35195"
    assert payload["component"]["name"] == "requests"
    assert payload["verdict"] == "affected"
    assert payload["reproducible"] is True
    assert payload["reach"]["status"] == "reachable_confirmed"
    assert payload["symbols"], "the symbols searched for belong in the payload"
    reaching = [
        entry for entry in payload["entry_points"]["examined"] if entry["status"] != "unreached"
    ]
    assert reaching and len(reaching[0]["path"]) >= 4


def test_reach_rejects_an_advisory_that_does_not_apply(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    environment = _synthetic_environment(fixture_repos_dir, tmp_path, "direct-call")
    result = runner.invoke(
        app,
        [
            "reach",
            str(fixture_repos_dir / "direct-call"),
            "--advisory",
            "CVE-9999-00001",
            "--environment",
            str(environment),
            "--no-cache",
        ],
    )
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)
    assert "no advisory matching" in result.stderr


def test_reach_accepts_symbols_by_hand(env: None, fixture_repos_dir: Path, tmp_path: Path) -> None:
    environment = _synthetic_environment(fixture_repos_dir, tmp_path, "unused-transitive")
    result = runner.invoke(
        app,
        [
            "reach",
            str(fixture_repos_dir / "unused-transitive"),
            "--advisory",
            "CVE-2023-45803",
            "--environment",
            str(environment),
            "--no-cache",
            "--symbol",
            "app.compute.mean",
        ],
    )
    assert "from manual" in result.stdout
    assert "command line" in result.stdout


def test_reach_requires_an_advisory() -> None:
    result = runner.invoke(app, ["reach", "."])
    assert result.exit_code != 0


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


# --- vex -------------------------------------------------------------------


def test_vex_export_writes_an_openvex_document(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    environment = _synthetic_environment(fixture_repos_dir, tmp_path, "unused-transitive")
    out = tmp_path / "doc.vex.json"
    result = runner.invoke(
        app,
        [
            "vex",
            "export",
            str(fixture_repos_dir / "unused-transitive"),
            "--author",
            "Example Org",
            "--product",
            "pkg:generic/my-service@1.0.0",
            "--environment",
            str(environment),
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 0
    document = json.loads(out.read_text(encoding="utf-8"))

    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert document["author"] == "Example Org"
    cleared = [s for s in document["statements"] if s["status"] == "not_affected"]
    assert cleared, "the unused dependency should be stated as not affected"
    # The product is what you ship; the dependency is a subcomponent.
    assert cleared[0]["products"][0]["@id"] == "pkg:generic/my-service@1.0.0"
    assert cleared[0]["products"][0]["subcomponents"][0]["@id"].startswith("pkg:pypi/")
    assert cleared[0]["justification"] == "vulnerable_code_not_in_execute_path"
    # The digest and statement counts go to stderr, so stdout stays pipeable.
    assert "sha256" in result.stderr


def test_vex_export_refuses_to_publish_anonymously(env: None, fixture_repos_dir: Path) -> None:
    result = runner.invoke(app, ["vex", "export", str(fixture_repos_dir / "direct-call")])
    assert result.exit_code == int(ExitCode.ANALYSIS_ERROR)
    assert "--author is required" in result.stderr


def test_vex_export_can_reuse_an_earlier_scan(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    """Re-deriving verdicts could produce a document that disagrees with the
    report it came from."""
    scanned = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--format", "json", "--no-reach"],
    )
    results = tmp_path / "results.json"
    results.write_text(scanned.stdout, encoding="utf-8")

    result = runner.invoke(app, ["vex", "export", "--author", "A", "--results", str(results)])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert [s["vulnerability"]["name"] for s in document["statements"]] == ["CVE-2024-35195"]
    # The scan ran without reachability, so matching's own verdict stands and
    # the document says what to do rather than claiming anything was cleared.
    assert document["statements"][0]["status"] == "affected"
    assert "Upgrade requests to 2.32.0" in document["statements"][0]["action_statement"]


def test_vex_export_is_byte_identical_across_runs(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    """What lets a document be diffed and makes its hash worth attesting."""
    scanned = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--format", "json", "--no-reach"],
    )
    results = tmp_path / "results.json"
    results.write_text(scanned.stdout, encoding="utf-8")

    first = runner.invoke(app, ["vex", "export", "--author", "A", "--results", str(results)])
    second = runner.invoke(app, ["vex", "export", "--author", "A", "--results", str(results)])
    assert first.stdout == second.stdout


# --- policy ----------------------------------------------------------------


def test_policy_list_describes_every_preset() -> None:
    result = runner.invoke(app, ["policy", "list"])
    assert result.exit_code == 0
    for name in ("strict", "balanced", "kev-only", "report-only"):
        assert name in result.stdout
    assert "(default)" in result.stdout
    # The convention that makes every mistake safe rather than silent.
    assert "true when the build must fail" in result.stdout


def test_policy_explain_lists_what_an_expression_can_read() -> None:
    result = runner.invoke(app, ["policy", "explain", "balanced"])
    assert result.exit_code == 0
    assert "findings[]" in result.stdout
    assert "reach{analysed" in result.stdout
    assert "compiled successfully" in result.stderr


def test_policy_explain_refuses_a_malformed_expression() -> None:
    result = runner.invoke(app, ["policy", "explain", "findings.exists(f, f.verdict ==="])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "not valid CEL" in result.stderr


def _scan_results(env: None, fixture_repos_dir: Path, tmp_path: Path) -> Path:
    scanned = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--format", "json", "--no-reach"],
    )
    path = tmp_path / "results.json"
    path.write_text(scanned.stdout, encoding="utf-8")
    return path


def test_policy_test_evaluates_against_an_earlier_scan(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    results = _scan_results(env, fixture_repos_dir, tmp_path)

    # The fixture's advisory is MEDIUM and was never proven reachable, so
    # balanced passes. Gating on anything outstanding at all does not.
    balanced = runner.invoke(app, ["policy", "test", "balanced", "--scan", str(results)])
    assert balanced.exit_code == 0
    assert "PASS" in balanced.stdout

    outstanding = runner.invoke(
        app, ["policy", "test", "nothing-outstanding", "--scan", str(results)]
    )
    assert outstanding.exit_code == int(ExitCode.POLICY_FAILED)
    assert "FAIL" in outstanding.stdout
    assert "CVE-2024-35195" in outstanding.stdout


def test_policy_test_reports_json_for_a_pipeline(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    results = _scan_results(env, fixture_repos_dir, tmp_path)
    result = runner.invoke(
        app, ["policy", "test", "nothing-outstanding", "--scan", str(results), "--format", "json"]
    )
    payload = json.loads(result.stdout)
    assert payload["name"] == "nothing-outstanding"
    assert payload["passed"] is False
    assert payload["violations"][0]["advisory_id"] == "CVE-2024-35195"
    assert payload["violations"][0]["rule"] == "nothing-outstanding"


def test_policy_test_accepts_an_expression_from_a_file(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    results = _scan_results(env, fixture_repos_dir, tmp_path)
    policy_file = tmp_path / "gate.cel"
    policy_file.write_text('findings.exists(f, f.component == "requests")\n', encoding="utf-8")

    result = runner.invoke(app, ["policy", "test", str(policy_file), "--scan", str(results)])
    assert result.exit_code == int(ExitCode.POLICY_FAILED)


def test_a_broken_policy_is_a_configuration_error_not_a_pass(
    env: None, fixture_repos_dir: Path, tmp_path: Path
) -> None:
    """The worst outcome would be a gate that silently stopped working."""
    results = _scan_results(env, fixture_repos_dir, tmp_path)
    result = runner.invoke(app, ["policy", "test", "size(findings)", "--scan", str(results)])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "rather than a boolean" in result.stderr


def test_scan_gates_on_a_policy(env: None, fixture_repos_dir: Path) -> None:
    passing = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach", "--policy", "balanced"],
    )
    assert passing.exit_code == 0
    assert "Policy balanced: passed" in passing.stdout

    failing = runner.invoke(
        app,
        [
            "scan",
            str(fixture_repos_dir / "direct-call"),
            "--no-reach",
            "--policy",
            "nothing-outstanding",
        ],
    )
    assert failing.exit_code == int(ExitCode.POLICY_FAILED)
    assert "nothing-outstanding" in failing.stdout


def test_a_scan_without_a_policy_gates_on_nothing(env: None, fixture_repos_dir: Path) -> None:
    """A scan asked only to report must not acquire an opinion."""
    result = runner.invoke(
        app, ["scan", str(fixture_repos_dir / "direct-call"), "--no-reach", "--format", "json"]
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["policy"] is None


def test_a_scan_with_a_broken_policy_exits_with_a_config_error(
    env: None, fixture_repos_dir: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture_repos_dir / "direct-call"),
            "--no-reach",
            "--policy",
            "findings.exists(f, f.verdict ===",
        ],
    )
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
