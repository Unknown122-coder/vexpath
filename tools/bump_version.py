"""Set one version everywhere it is written.

Eleven places across nine files: the `version` of each of the six packages,
the exact-version pins the dependent packages carry, the version the GitHub
Action installs, and the committed OpenAPI document, which carries the API's
version in `info.version`. Doing that by hand is how a release ends up with
`vexpath` at one version depending on a `vexpath-core` at another, which
resolves to nothing and is only discovered by somebody installing from PyPI.

The OpenAPI document was the one that got missed, and a test caught it in the
release pipeline rather than before the tag. It is regenerated here now,
because "everywhere the version is written" has to mean everywhere.

Tests already refuse a mismatch -- every package must share one version, every
workspace dependency must be pinned to it, and the Action's pin must match the
command line's. This exists so the mismatch does not happen in the first
place.

    uv run python tools/bump_version.py 0.1.0
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Every package, in no particular order: they all get the same version.
MANIFESTS = (
    ROOT / "packages" / "core" / "pyproject.toml",
    ROOT / "packages" / "platform" / "pyproject.toml",
    ROOT / "packages" / "db" / "pyproject.toml",
    ROOT / "packages" / "cli" / "pyproject.toml",
    ROOT / "apps" / "api" / "pyproject.toml",
    ROOT / "apps" / "worker" / "pyproject.toml",
)

#: The packages that are depended on by name and pinned by version.
SIBLINGS = ("vexpath-core", "vexpath-platform", "vexpath-db")

ACTION = ROOT / "apps" / "action" / "action.yml"

#: PEP 440, loosely: enough to refuse a typo without reimplementing the spec.
#: A bad version reaches PyPI as a different release than the one intended,
#: and a release cannot be taken back.
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|\.dev\d+|\.post\d+)?$")


def bump(version: str) -> list[str]:
    changed: list[str] = []

    for manifest in MANIFESTS:
        text = manifest.read_text(encoding="utf-8")
        before = text

        # Only the first `version = ` line: a dependency's own specifier must
        # not be rewritten by accident.
        text = re.sub(r'^version = "[^"]+"', f'version = "{version}"', text, count=1, flags=re.M)

        for sibling in SIBLINGS:
            text = re.sub(
                rf'"{sibling}==[^"]+"',
                f'"{sibling}=={version}"',
                text,
            )

        if text != before:
            manifest.write_text(text, encoding="utf-8")
            changed.append(str(manifest.relative_to(ROOT)))

    action = ACTION.read_text(encoding="utf-8")
    updated = re.sub(r'pinned="[^"]+"', f'pinned="{version}"', action, count=1)
    if updated != action:
        ACTION.write_text(updated, encoding="utf-8")
        changed.append(str(ACTION.relative_to(ROOT)))

    if _regenerate_openapi():
        changed.append("apps/api/openapi.json")

    return changed


def _regenerate_openapi() -> bool:
    """Rewrite the committed OpenAPI document, which carries the version.

    Run as a subprocess rather than imported, because the exporter builds an
    application and this tool should not have to. Returns whether the file
    changed; a failure is reported rather than swallowed, since a stale
    document fails the release pipeline either way and the message here is
    the clearer one.
    """
    exporter = ROOT / "tools" / "export_openapi.py"
    result = subprocess.run(  # noqa: S603 - a fixed command, built here
        [sys.executable, str(exporter)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(ROOT),
    )
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        msg = "the OpenAPI document could not be regenerated"
        raise SystemExit(msg)
    return "wrote" in result.stdout


def verify(version: str) -> list[str]:
    """Read everything back and report anything that disagrees."""
    problems: list[str] = []

    for manifest in MANIFESTS:
        project = tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]
        name = project["name"]
        if project["version"] != version:
            problems.append(f"{name} is at {project['version']}")
        for requirement in project.get("dependencies", []):
            for sibling in SIBLINGS:
                if (
                    requirement.startswith(f"{sibling}==")
                    and requirement != f"{sibling}=={version}"
                ):
                    problems.append(f"{name} requires {requirement}")

    action = ACTION.read_text(encoding="utf-8")
    match = re.search(r'pinned="([^"]+)"', action)
    if match is None:
        problems.append("the Action pins no version")
    elif match.group(1) != version:
        problems.append(f"the Action pins {match.group(1)}")

    schema = json.loads((ROOT / "apps" / "api" / "openapi.json").read_text(encoding="utf-8"))
    if schema["info"]["version"] != version:
        problems.append(f"the OpenAPI document says {schema['info']['version']}")

    return problems


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    version = sys.argv[1].lstrip("v")
    if not VERSION.match(version):
        print(f"{version!r} does not look like a version", file=sys.stderr)
        return 2

    for path in bump(version):
        print(f"updated {path}")

    problems = verify(version)
    if problems:
        print("\nsomething still disagrees:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(f"\nevery package, every pin and the Action are at {version}")
    print(f"next: make dist, then  git tag -s v{version} -m v{version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
