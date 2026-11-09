"""Run the reachability benchmark over real repositories.

This is M2's acceptance gate. The engine working on six fixtures proves the
algorithm; this measures what it does to code nobody wrote for it.

What it can and cannot measure, stated plainly because the difference decides
what the numbers are worth:

**It can measure noise reduction.** The share of findings that move from
needing attention to cleared is the product's whole claim, and it is a fact
about the run.

**It can measure soundness preconditions.** Every clearance is checked against
the rules that are supposed to make one legitimate: the package's own graph was
linked, the advisory named symbols, those symbols exist in the installed
version, and none was reached. A clearance failing any of those is a bug in the
verdict layer and fails the benchmark.

**It cannot measure true exploitability.** Nobody has ground truth for whether
a real application can really execute a vulnerable function, so a false-clear
rate is not computable here. The fixture benchmark covers that with cases whose
answer is known by construction; this one covers scale, shape and crash
resistance.

**It cannot be fast.** Every project is cloned and every dependency's source is
downloaded. The run is bounded per project and resumable: results are written
as each project finishes.

Usage:
    uv run python tools/run_benchmark.py --snapshot var/enriched
    uv run python tools/run_benchmark.py --snapshot var/enriched --only flask,click
    uv run python tools/run_benchmark.py --snapshot var/enriched --limit 5
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPOSITORY_ROOT / "testdata" / "benchmark" / "projects.yaml"
RESULTS = REPOSITORY_ROOT / "testdata" / "benchmark" / "results.json"

#: Per project. A clone plus a scan that downloads every dependency's source
#: is minutes, not seconds, and one project hanging must not cost the run.
PROJECT_TIMEOUT_SECONDS = 1200

#: Shallow and blobless: the benchmark reads source files, and a full history
#: of pandas or airflow is gigabytes of data nothing here looks at.
CLONE_ARGUMENTS = ("--depth=1", "--filter=blob:none", "--no-tags", "--quiet")


@dataclass
class ProjectResult:
    """What one project's scan produced."""

    name: str
    status: str
    seconds: float = 0.0
    components: int = 0
    findings: int = 0
    reachable: int = 0
    possibly_reachable: int = 0
    cleared: int = 0
    under_investigation: int = 0
    linked_packages: int = 0
    first_party_nodes: int = 0
    unresolved_call_ratio: float = 0.0
    parse_error_ratio: float = 0.0
    entry_point_source: str = ""
    entry_points: int = 0
    #: Clearances that broke a soundness precondition. Any entry here is a bug.
    unsound_clearances: list[str] = field(default_factory=list)
    #: Advisories this project matched, so symbol extraction can be aimed at
    #: what real projects actually hit rather than at the queue's head.
    advisories: list[str] = field(default_factory=list)
    #: Advisories left under investigation for want of symbols. Extracting
    #: these is what would turn this project's noise reduction into a real
    #: number.
    awaiting_symbols: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def needs_attention(self) -> int:
        return self.reachable + self.possibly_reachable + self.under_investigation

    @property
    def noise_reduction(self) -> float:
        return self.cleared / self.findings if self.findings else 0.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot",
        type=Path,
        required=True,
        help="Advisory snapshot to scan against. Use one with extracted symbols.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=REPOSITORY_ROOT / "var" / "benchmark",
        help="Where to clone projects.",
    )
    parser.add_argument("--only", default="", help="Comma-separated project names to run.")
    parser.add_argument("--limit", type=int, default=0, help="Run at most this many projects.")
    parser.add_argument(
        "--keep-clones",
        action="store_true",
        help="Leave clones on disk. Faster to re-run, and tens of gigabytes.",
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=RESULTS,
        help="Where to write the result file.",
    )
    arguments = parser.parse_args(argv)

    if not arguments.snapshot.is_dir():
        print(f"no snapshot at {arguments.snapshot}", file=sys.stderr)
        return 3

    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    projects: list[dict[str, Any]] = manifest["projects"]

    wanted = {name.strip() for name in arguments.only.split(",") if name.strip()}
    if wanted:
        projects = [project for project in projects if project["name"] in wanted]
    if arguments.limit:
        projects = projects[: arguments.limit]

    arguments.work_dir.mkdir(parents=True, exist_ok=True)
    results: list[ProjectResult] = []

    for index, project in enumerate(projects, start=1):
        name = project["name"]
        print(f"[{index}/{len(projects)}] {name}", flush=True)
        result = _run_project(project, arguments)
        results.append(result)
        print(f"    {_describe(result)}", flush=True)
        # Written as each finishes, so a run killed halfway still has numbers.
        _write(arguments.results, results)
        if not arguments.keep_clones:
            shutil.rmtree(arguments.work_dir / name, ignore_errors=True)

    _summarise(results)
    return 1 if any(result.unsound_clearances for result in results) else 0


def _run_project(project: dict[str, Any], arguments: argparse.Namespace) -> ProjectResult:
    name = project["name"]
    checkout = arguments.work_dir / name
    started = time.monotonic()

    if not checkout.is_dir():
        cloned = _clone(project["repo"], project.get("ref", "HEAD"), checkout)
        if cloned is not None:
            return ProjectResult(
                name=name, status="clone_failed", detail=cloned, seconds=time.monotonic() - started
            )

    payload, failure = _scan(checkout, arguments.snapshot)
    seconds = time.monotonic() - started
    if payload is None:
        return ProjectResult(name=name, status="scan_failed", detail=failure, seconds=seconds)

    return _measure(name, payload, seconds)


def _clone(repository: str, ref: str, destination: Path) -> str | None:
    """Clone one project, returning an error string or None on success."""
    command = ["git", "clone", *CLONE_ARGUMENTS, "--branch", ref, repository, str(destination)]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, no shell
            command,
            capture_output=True,
            text=True,
            timeout=PROJECT_TIMEOUT_SECONDS,
            check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return f"{type(exc).__name__}: {exc}"
    if completed.returncode != 0:
        return (completed.stderr or completed.stdout).strip()[:300]
    return None


def _scan(checkout: Path, snapshot: Path) -> tuple[dict[str, Any] | None, str]:
    """Run the real command, exactly as a user would."""
    command = [
        sys.executable,
        "-m",
        "vexpath.main",
        "scan",
        str(checkout),
        "--snapshot",
        str(snapshot),
        "--download-missing",
        "--format",
        "json",
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, no shell
            command,
            capture_output=True,
            text=True,
            timeout=PROJECT_TIMEOUT_SECONDS,
            check=False,
            cwd=REPOSITORY_ROOT,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"

    if not completed.stdout.strip():
        return None, (completed.stderr or "no output").strip()[:400]
    try:
        return json.loads(completed.stdout), ""
    except json.JSONDecodeError as exc:
        return None, f"output was not JSON: {exc}"


def _measure(name: str, payload: dict[str, Any], seconds: float) -> ProjectResult:
    findings = payload.get("findings") or []
    graph = payload.get("graph") or {}
    entry_points = payload.get("entry_points") or {}

    counts = {"affected": 0, "not_affected": 0, "under_investigation": 0}
    reachable = 0
    possible = 0
    unsound: list[str] = []
    matched: list[str] = []
    awaiting: list[str] = []

    for finding in findings:
        verdict = str(finding.get("verdict") or "")
        counts[verdict] = counts.get(verdict, 0) + 1
        reach = finding.get("reach") or {}
        status = str(reach.get("status") or "")
        identifier = str((finding.get("advisory") or {}).get("id") or "")
        if identifier:
            matched.append(identifier)
            if reach.get("reason") == "no_fix_commit":
                awaiting.append(identifier)
        if status == "reachable_confirmed":
            reachable += 1
        elif status == "reachable_possible":
            possible += 1
        if verdict == "not_affected":
            problem = _check_clearance(finding, reach)
            if problem is not None:
                unsound.append(problem)

    return ProjectResult(
        name=name,
        status="ok",
        seconds=round(seconds, 1),
        components=int((payload.get("sbom") or {}).get("component_count") or 0),
        findings=len(findings),
        reachable=reachable,
        possibly_reachable=possible,
        cleared=counts.get("not_affected", 0),
        under_investigation=counts.get("under_investigation", 0),
        linked_packages=int(graph.get("linked_packages") or 0),
        first_party_nodes=int(graph.get("first_party_nodes") or 0),
        unresolved_call_ratio=float(graph.get("unresolved_call_ratio") or 0.0),
        parse_error_ratio=float(graph.get("parse_error_ratio") or 0.0),
        entry_point_source=str(entry_points.get("source") or ""),
        entry_points=int(entry_points.get("count") or 0),
        unsound_clearances=unsound,
        advisories=sorted(set(matched)),
        awaiting_symbols=sorted(set(awaiting)),
    )


def _check_clearance(finding: dict[str, Any], reach: dict[str, Any]) -> str | None:
    """Check one clearance against the rules that make one legitimate.

    Only proven unreachability may clear a finding. The verdict layer enforces
    that and the model validator enforces it again, so anything caught here is
    a bug in both, which is exactly why it is worth checking from outside.
    """
    advisory = (finding.get("advisory") or {}).get("id", "?")
    component = (finding.get("component") or {}).get("name", "?")
    where = f"{advisory} on {component}"

    if reach.get("status") != "unreachable":
        return f"{where}: cleared with status {reach.get('status')!r}, not 'unreachable'"
    if not reach.get("searched_symbols"):
        return f"{where}: cleared without naming any symbol it searched for"
    if reach.get("matched_symbols"):
        return f"{where}: cleared while reporting matched symbols {reach['matched_symbols']}"
    if finding.get("justification") != "vulnerable_code_not_in_execute_path":
        return f"{where}: cleared with justification {finding.get('justification')!r}"
    graph = reach.get("graph_stats") or {}
    if not graph.get("linked_packages"):
        return f"{where}: cleared with no dependency graph linked"
    entry_points = reach.get("entry_points") or {}
    if not entry_points.get("count"):
        return f"{where}: cleared with no entry points to search from"
    return None


def _describe(result: ProjectResult) -> str:
    if result.status != "ok":
        return f"{result.status}: {result.detail[:160]}"
    return (
        f"{result.findings} findings, {result.cleared} cleared "
        f"({result.noise_reduction:.0%}), {result.reachable} reachable, "
        f"{result.under_investigation} under investigation, "
        f"{result.linked_packages} packages linked, {result.seconds:.0f}s"
    )


def _write(path: Path, results: list[ProjectResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "projects": [asdict(result) for result in results],
        "totals": _totals(results),
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


def _totals(results: list[ProjectResult]) -> dict[str, Any]:
    scanned = [result for result in results if result.status == "ok"]
    findings = sum(result.findings for result in scanned)
    cleared = sum(result.cleared for result in scanned)
    return {
        "projects": len(results),
        "scanned": len(scanned),
        "failed": len(results) - len(scanned),
        "findings": findings,
        "cleared": cleared,
        "reachable": sum(result.reachable for result in scanned),
        "possibly_reachable": sum(result.possibly_reachable for result in scanned),
        "under_investigation": sum(result.under_investigation for result in scanned),
        "noise_reduction": round(cleared / findings, 4) if findings else 0.0,
        "unsound_clearances": sum(len(result.unsound_clearances) for result in scanned),
        # The ceiling on noise reduction: a finding whose advisory names no
        # symbols cannot be cleared by any amount of graph work.
        "awaiting_symbols": len(
            {identifier for result in scanned for identifier in result.awaiting_symbols}
        ),
        "advisories": len({identifier for result in scanned for identifier in result.advisories}),
    }


def _summarise(results: list[ProjectResult]) -> None:
    totals = _totals(results)
    print()
    print("Benchmark")
    print(f"  projects scanned      {totals['scanned']} of {totals['projects']}")
    print(f"  findings              {totals['findings']}")
    print(f"  cleared as unreachable{totals['cleared']:>6}  ({totals['noise_reduction']:.1%})")
    print(f"  reachable             {totals['reachable']}")
    print(f"  possibly reachable    {totals['possibly_reachable']}")
    print(f"  under investigation   {totals['under_investigation']}")
    print(f"  unsound clearances    {totals['unsound_clearances']}")
    print(f"  distinct advisories   {totals['advisories']}")
    print(f"  awaiting symbols      {totals['awaiting_symbols']}")

    failures = [result for result in results if result.status != "ok"]
    if failures:
        print()
        print("Did not scan")
        for result in failures:
            print(f"  {result.name}: {result.status} {result.detail[:120]}")

    unsound = [result for result in results if result.unsound_clearances]
    if unsound:
        print()
        print("UNSOUND CLEARANCES, each one a bug")
        for result in unsound:
            for problem in result.unsound_clearances:
                print(f"  {result.name}: {problem}")


if __name__ == "__main__":
    raise SystemExit(main())
