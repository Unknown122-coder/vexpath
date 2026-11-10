"""The Action's contract, and the commands it actually runs.

A composite action cannot be executed outside a runner, so these tests do the
two things that can be done here and are worth doing.

**They check the contract.** Every input the README documents exists, every
output is wired to a step that produces it, the pinned version matches the
command line's own, and every command the action invokes is one the command
line has. That last one is the failure that would otherwise appear as a red
build in somebody else's repository: a renamed flag breaks the action silently,
because nothing in this repository calls it.

**They run the commands.** The scan-render-summarise-gate sequence is exercised
directly against a fixture project, in the same order the action runs it, so
the pipeline the YAML describes is known to work even though the YAML itself
is only read.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from vexpath import __version__ as cli_version
from vexpath.exit_codes import ExitCode
from vexpath.main import app

ACTION = Path(__file__).resolve().parents[1] / "action.yml"
README = Path(__file__).resolve().parents[1] / "README.md"

runner = CliRunner()


@pytest.fixture(scope="module")
def action() -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    return document


def _steps(action: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = action["runs"]["steps"]
    return steps


def _scripts(action: dict[str, Any]) -> str:
    return "\n".join(step.get("run", "") for step in _steps(action))


# --- The contract ----------------------------------------------------------


def test_it_is_a_composite_action(action: dict[str, Any]) -> None:
    # Not a container action: reachability needs the caller's dependencies
    # readable on disk, and a container has its own filesystem where their
    # virtual environment does not exist. Every finding would come back
    # "package not analysed" and nothing could ever be cleared.
    assert action["runs"]["using"] == "composite"


def test_the_pinned_version_is_one_that_exists(action: dict[str, Any]) -> None:
    script = _scripts(action)
    match = re.search(r'pinned="([^"]+)"', script)
    assert match is not None, "the action does not pin a version"
    # Otherwise the action ships pointing at a release that was never made,
    # and the failure is a pip error in somebody else's build.
    assert match.group(1) == cli_version


def test_every_output_is_wired_to_a_step_that_sets_it(action: dict[str, Any]) -> None:
    identifiers = {step["id"] for step in _steps(action) if "id" in step}
    script = _scripts(action)
    for name, spec in action["outputs"].items():
        reference = re.search(r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", spec["value"])
        assert reference is not None, name
        step, key = reference.groups()
        assert step in identifiers, f"{name} reads a step that does not exist: {step}"
        # The step has to actually write it. A declared output nothing sets is
        # an empty string in the caller's workflow, which is worse than a
        # missing one because it looks like an answer.
        assert f"{key}=" in script or "--summary" in script, f"{name} is never set"


def test_the_counts_come_from_the_tool_and_not_from_yaml(action: dict[str, Any]) -> None:
    script = _scripts(action)
    # What counts as "needs attention" or "reachable" is a decision this
    # project has made. A second implementation parsing JSON in a shell step
    # would eventually disagree with the report printed beside it.
    assert "vexpath report vexpath-results.json --summary" in script
    assert "json.loads" not in script


def test_nothing_is_rendered_by_re_running_the_scan(action: dict[str, Any]) -> None:
    script = _scripts(action)
    # One analysis, three renderings. A second scan against a corpus that has
    # moved on reaches different verdicts, so the SARIF uploaded would not
    # match the table in the log.
    assert script.count("vexpath scan ") == 1
    assert script.count("vexpath report ") >= 3


def test_the_gate_runs_last(action: dict[str, Any]) -> None:
    names = [step["name"] for step in _steps(action)]
    # So a build that fails the gate still has its report, its SARIF, its
    # comment and its uploaded record. The run that fails is the one somebody
    # most needs to read.
    assert names[-1] == "Apply the policy"
    for earlier in ("Scan", "Render", "Job summary"):
        assert names.index(earlier) < names.index("Apply the policy")


def test_the_scan_step_does_not_apply_the_policy(action: dict[str, Any]) -> None:
    scan = next(step for step in _steps(action) if step.get("id") == "scan")
    # If the scan applied the gate it would exit non-zero before writing
    # anything, and there would be nothing left to render or upload.
    assert "--policy" not in scan["run"]


def test_it_does_not_pull_in_another_action(action: dict[str, Any]) -> None:
    # A supply-chain security tool that silently added three more actions to
    # your build would be an odd thing to trust. SARIF upload and caching are
    # two lines in the caller's workflow, documented in the README.
    assert all("uses" not in step for step in _steps(action))


def test_the_cache_directory_is_asked_of_the_tool(action: dict[str, Any]) -> None:
    script = _scripts(action)
    # Rather than hardcoded, so it cannot drift from
    # vexpath_core.reach.cache.default_cache_directory.
    assert "default_cache_directory" in script


def test_every_shell_step_fails_on_an_error(action: dict[str, Any]) -> None:
    for step in _steps(action):
        if "run" not in step:
            continue
        # Without this a failing command inside a multi-line script is
        # ignored and the step reports success, which for a security gate is
        # the worst available outcome.
        assert "set -euo pipefail" in step["run"], step["name"]
        assert step["shell"] == "bash"


def test_the_optional_steps_are_conditional(action: dict[str, Any]) -> None:
    by_name = {step["name"]: step for step in _steps(action)}
    for name in (
        "Comment on the pull request",
        "Sign the result",
        "Upload to the platform",
        "Apply the policy",
    ):
        assert "if" in by_name[name], name
    # The comment is additionally gated on being a pull request, because
    # `gh pr comment` has nothing to attach to otherwise.
    assert "pull_request" in by_name["Comment on the pull request"]["if"]


def test_the_readme_documents_every_input_and_output(action: dict[str, Any]) -> None:
    text = README.read_text(encoding="utf-8")
    for name in action["inputs"]:
        assert f"`{name}`" in text, f"input {name} is not in the README"
    for name in action["outputs"]:
        assert f"`{name}`" in text, f"output {name} is not in the README"


def test_the_readme_explains_the_permissions_each_feature_needs() -> None:
    text = README.read_text(encoding="utf-8")
    for permission in ("security-events: write", "pull-requests: write", "id-token: write"):
        assert permission in text


# --- The commands it runs --------------------------------------------------


def test_every_command_the_action_runs_exists(action: dict[str, Any]) -> None:
    script = _scripts(action)
    invoked = sorted(set(re.findall(r"vexpath ([a-z-]+)", script)))
    assert invoked, "the action runs no vexpath commands"

    help_text = runner.invoke(app, ["--help"]).stdout
    for command in invoked:
        # A renamed command or flag breaks the action silently, because
        # nothing else in this repository calls it.
        assert command in help_text, f"vexpath has no '{command}' command"


def test_the_sequence_the_action_describes_works(
    tmp_path: Path, fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    """Scan, render three ways, summarise, gate -- in that order.

    The YAML can only be read here, so the pipeline it describes is run
    directly instead. A change that breaks the order or a flag fails here
    rather than in somebody else's repository.
    """
    environment = {"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)}
    results = tmp_path / "vexpath-results.json"

    scanned = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--format", "json", "--no-reach"],
        env=environment,
    )
    assert scanned.exit_code == 0, scanned.output
    results.write_text(scanned.stdout, encoding="utf-8")

    sarif = tmp_path / "vexpath.sarif"
    markdown = tmp_path / "vexpath.md"
    assert (
        runner.invoke(
            app, ["report", str(results), "--format", "sarif", "--output", str(sarif)]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["report", str(results), "--format", "markdown", "--output", str(markdown)]
        ).exit_code
        == 0
    )
    assert json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert markdown.read_text(encoding="utf-8").lstrip().startswith("#")

    summary = runner.invoke(app, ["report", str(results), "--summary"])
    assert summary.exit_code == 0
    counts = dict(line.split("=", 1) for line in summary.stdout.strip().splitlines() if "=" in line)
    # Exactly the names the action's outputs use.
    for key in ("needs_attention", "cleared", "reachable", "policy_passed"):
        assert key in counts

    # The fixture's finding is affected at medium severity, which the strict
    # preset deliberately lets through -- it gates on critical and high. The
    # distinction is the product, so both directions are asserted.
    lenient = runner.invoke(app, ["policy", "test", "strict", "--scan", str(results)])
    assert lenient.exit_code == 0, lenient.output

    gated = runner.invoke(app, ["policy", "test", "nothing-outstanding", "--scan", str(results)])
    # Failing is exit 1, never 2: a vulnerable build must not look like a
    # broken tool.
    assert gated.exit_code == int(ExitCode.POLICY_FAILED)


def test_the_report_only_preset_lets_a_build_through(
    tmp_path: Path, fixture_repos_dir: Path, snapshot_dir: Path
) -> None:
    environment = {"VEXPATH_ADVISORY_SNAPSHOT_DIR": str(snapshot_dir)}
    scanned = runner.invoke(
        app,
        ["scan", str(fixture_repos_dir / "direct-call"), "--format", "json", "--no-reach"],
        env=environment,
    )
    results = tmp_path / "results.json"
    results.write_text(scanned.stdout, encoding="utf-8")
    # Named rather than left implicit, so a configuration can say "we have
    # decided not to gate" instead of appearing unfinished.
    assert (
        runner.invoke(app, ["policy", "test", "report-only", "--scan", str(results)]).exit_code == 0
    )
