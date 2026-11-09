"""The ``vexpath policy`` command group: read, test and explain the gate.

A gate nobody can try out before pushing is a gate that gets disabled. These
commands exist so a policy can be written, run against a scan that already
happened, and understood without reading the source.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vexpath.exit_codes import ExitCode
from vexpath.output import OutputFormat, emit, emit_json, fail, fail_config, note
from vexpath_core import policy as policy_module
from vexpath_core.models.results import ScanResults

app = typer.Typer(help="Write, test and explain the build gate.", no_args_is_help=True)


@app.command("list")
def list_presets(
    output: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Show the named policies and what each one does."""
    payload = [
        {
            "name": name,
            "default": name == policy_module.DEFAULT_PRESET,
            "description": policy_module.explain(name),
            "expression": expression,
        }
        for name, expression in policy_module.PRESETS.items()
    ]
    if output is OutputFormat.JSON:
        emit_json(payload)
        return

    lines: list[str] = []
    for entry in payload:
        marker = " (default)" if entry["default"] else ""
        lines.append(f"{entry['name']}{marker}")
        lines.append(f"  {entry['description']}")
        lines.append(f"  {entry['expression']}")
        lines.append("")
    lines.append("An expression evaluates to true when the build must fail.")
    emit("\n".join(lines) + "\n")


@app.command("test")
def test(
    policy: Annotated[
        str,
        typer.Argument(help=("A preset name, a CEL expression, or a path to a file holding one.")),
    ],
    results_file: Annotated[
        Path,
        typer.Option(
            "--scan",
            exists=True,
            dir_okay=False,
            help="JSON output of a scan to evaluate the policy against.",
        ),
    ],
    output: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Evaluate a policy against a scan that already ran.

    Nothing is re-scanned, so this is fast and gives the same answer CI will:
    the policy reads only what the scan concluded.

    Exits 1 when the policy fails, 3 when the policy itself cannot be
    compiled. A broken policy is never reported as a passing one.
    """
    source = _read_policy(policy)
    try:
        compiled = policy_module.compile_policy(source)
    except policy_module.PolicyError as exc:
        fail_config(str(exc))

    try:
        results = ScanResults.model_validate_json(results_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"{results_file} is not a vexpath scan result: {exc}")

    try:
        outcome = compiled.evaluate(results)
    except policy_module.PolicyError as exc:
        fail_config(str(exc))

    if output is OutputFormat.JSON:
        emit_json(outcome.model_dump(mode="json"))
    else:
        emit(_render(compiled, outcome, len(results.findings)))

    if not outcome.passed:
        raise typer.Exit(code=int(ExitCode.POLICY_FAILED))


def _read_policy(source: str) -> str:
    """Treat the argument as a file when it names one, else as a policy.

    A preset name wins over a file of the same name, because the presets are a
    closed vocabulary and a file called ``balanced`` sitting in a working
    directory should not silently change what the default means.
    """
    if source in policy_module.PRESETS:
        return source
    candidate = Path(source)
    if candidate.is_file():
        try:
            return candidate.read_text(encoding="utf-8").strip()
        except OSError as exc:
            fail_config(f"{candidate} could not be read: {exc}")
    return source


def _render(compiled: policy_module.CompiledPolicy, outcome: object, finding_count: int) -> str:
    from vexpath_core.models.results import PolicyResult

    assert isinstance(outcome, PolicyResult)  # narrowed for the type checker
    lines = [
        f"policy          {compiled.name}",
        f"expression      {compiled.expression}",
        f"findings        {finding_count}",
        f"result          {'PASS' if outcome.passed else 'FAIL'}",
    ]
    if outcome.violations:
        lines.append("")
        lines.append("Why it failed")
        for violation in outcome.violations:
            lines.append(f"  {violation.message}")
            if violation.component:
                lines.append(f"      {violation.component}")
    return "\n".join(lines) + "\n"


@app.command("explain")
def explain(
    policy: Annotated[str, typer.Argument(help="A preset name or a CEL expression.")],
) -> None:
    """Show what a policy would gate on, without running it.

    Useful for checking that an expression compiles before committing it, and
    for seeing which preset an inherited configuration actually resolved to.
    """
    source = _read_policy(policy)
    try:
        compiled = policy_module.compile_policy(source)
    except policy_module.PolicyError as exc:
        fail_config(str(exc))

    description = policy_module.explain(compiled.name)
    lines = [f"policy          {compiled.name}"]
    if description:
        lines.append(f"intent          {description}")
    lines.append(f"expression      {compiled.expression}")
    lines.append("")
    lines.append("True means the build fails. Available in an expression:")
    lines.append("  findings[]  advisory, component, purl, severity, severity_rank,")
    lines.append("              cvss, cvss_v4, epss, kev, verdict, justification,")
    lines.append("              fixed_in, has_fix, age_days, scope, direct, suppressed,")
    lines.append("              reach{analysed, status, reason, confidence,")
    lines.append("                    confidence_rank, reachable, path_length,")
    lines.append("                    via_dynamic_edges}")
    lines.append("  scan        mode, git_ref, git_sha, reproducible, snapshot")
    lines.append("  project     slug")
    lines.append("  counts      affected, not_affected, under_investigation, fixed")
    emit("\n".join(lines) + "\n")
    note("compiled successfully")


__all__ = ["app"]
