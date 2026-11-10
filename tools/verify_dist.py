"""Build the distributions and prove one installs and runs on its own.

This exists because the test suite cannot see the bug it catches. Everything
runs inside the workspace, where every package is already installed, so a
module imported without being declared as a dependency works perfectly — until
somebody installs the wheel, where it fails with ``ModuleNotFoundError``. That
happened: the command-line tool imported ``vexpath_platform`` for three
constants, and a published ``vexpath`` would have been broken on install.

So this builds, installs into an empty environment, and runs the command.
``make dist`` calls it, and it is the last check before a release.

**It installs with the cache disabled, and that is not paranoia.** A wheel
rebuilt at the same version with different contents is a cache hit: the first
run of this script "passed" against a stale ``vexpath-core`` and reported a
module missing that was in the new wheel all along. The same hazard applies to
a real release, which is why a release bumps the version rather than replacing
one.

    uv run python tools/verify_dist.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

#: What the installed command must be able to do. Not an exhaustive test --
#: the suite covers behaviour -- but enough that an import error, a missing
#: console script or a broken dependency cannot get past it.
CHECKS = (
    ("version", ["version"]),
    ("help", ["--help"]),
    (
        "scan",
        [
            "scan",
            str(ROOT / "testdata" / "repos" / "direct-call"),
            "--no-reach",
            "--snapshot",
            str(ROOT / "testdata" / "advisories"),
        ],
    ),
    ("report schema", ["version", "--format", "json"]),
)


def run(
    command: list[str], *, cwd: str | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    r"""Run a command and capture everything it said.

    The environment is *merged* rather than replaced. Replacing it dropped
    TEMP, which sent uv looking for a scratch directory in C:\WINDOWS and
    produced "Access is denied" -- a permissions error that had nothing to do
    with permissions.
    """
    return subprocess.run(  # noqa: S603 - fixed commands built here
        command,
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
        env=None if env is None else {**os.environ, **env},
    )


def build() -> list[Path]:
    if DIST.exists():
        shutil.rmtree(DIST)
    built = run(["uv", "build", "--all-packages", "-o", str(DIST)], cwd=str(ROOT))
    if built.returncode != 0:
        print(built.stdout)
        print(built.stderr, file=sys.stderr)
        msg = "the build failed"
        raise SystemExit(msg)
    wheels = sorted(DIST.glob("*.whl"))
    print(f"built {len(wheels)} wheels and {len(sorted(DIST.glob('*.tar.gz')))} source archives")
    return wheels


def inspect_archives() -> None:
    """Refuse an archive whose members escape its own root.

    Every package once carried ``license-files = ["../../LICENSE"]``, which
    put ``<name>-<version>/../../LICENSE`` into each source archive: a tar
    member pointing outside the directory it unpacks into, which is the
    path-traversal shape that archive extractors are supposed to refuse. One
    version of uv read it happily and a newer one refused, so the local build
    passed while the release pipeline failed -- and the archive was malformed
    either way.

    Checked here, by reading the files, so the answer does not depend on which
    builder or installer happens to be present.
    """
    import tarfile
    import zipfile

    problems: list[str] = []

    for archive in sorted(DIST.glob("*.tar.gz")):
        with tarfile.open(archive) as handle:
            names = handle.getnames()
        root = archive.name[: -len(".tar.gz")]
        for name in names:
            if ".." in Path(name).parts or Path(name).is_absolute():
                problems.append(f"{archive.name}: member escapes its root: {name}")
        if not any(Path(name).name == "LICENSE" for name in names):
            # Apache 2.0 asks that the licence travel with the source.
            problems.append(f"{archive.name}: carries no LICENSE")
        if not any(name.startswith(f"{root}/") for name in names):
            problems.append(f"{archive.name}: nothing under {root}/")

    for archive in sorted(DIST.glob("*.whl")):
        with zipfile.ZipFile(archive) as handle:
            names = handle.namelist()
        for name in names:
            if ".." in Path(name).parts or Path(name).is_absolute():
                problems.append(f"{archive.name}: member escapes its root: {name}")
        if not any(name.endswith("LICENSE") for name in names):
            problems.append(f"{archive.name}: carries no LICENSE")

    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        msg = "the distributions are malformed"
        raise SystemExit(msg)

    print(
        f"inspected {len(sorted(DIST.glob('*.tar.gz')))} source archives and "
        f"{len(sorted(DIST.glob('*.whl')))} wheels: no escaping members, every one carries its licence"
    )


def verify(wheels: list[Path]) -> None:
    command_line = next((w for w in wheels if w.name.startswith("vexpath-")), None)
    if command_line is None:
        msg = "no vexpath wheel was built"
        raise SystemExit(msg)

    with tempfile.TemporaryDirectory(prefix="vexpath-dist-") as temporary:
        environment = Path(temporary) / "venv"
        created = run(["uv", "venv", str(environment)])
        if created.returncode != 0:
            print(created.stderr, file=sys.stderr)
            msg = "the environment could not be created"
            raise SystemExit(msg)

        installed = run(
            [
                "uv",
                "pip",
                "install",
                # No cache: a wheel rebuilt at the same version with different
                # contents is otherwise a cache hit, and this script would
                # verify the previous build.
                "--no-cache",
                "--find-links",
                str(DIST),
                str(command_line),
            ],
            env={"VIRTUAL_ENV": str(environment)},
        )
        if installed.returncode != 0:
            print(installed.stdout)
            print(installed.stderr, file=sys.stderr)
            msg = "the wheel could not be installed on its own"
            raise SystemExit(msg)

        executable = _console_script(environment)
        if not executable.exists():
            msg = f"the console script is missing: {executable}"
            raise SystemExit(msg)

        for label, arguments in CHECKS:
            result = run([str(executable), *arguments])
            if result.returncode != 0:
                print(result.stdout)
                print(result.stderr, file=sys.stderr)
                msg = f"the installed command failed: {label}"
                raise SystemExit(msg)
            print(f"ok: {label}")

    print("the command line installs and runs with nothing else present")


def _console_script(environment: Path) -> Path:
    # os.name rather than sys.platform: a type checker special-cases the
    # latter and calls the other branch dead code, which is exactly the
    # branch that matters on the other platform.
    if os.name == "nt":
        return environment / "Scripts" / "vexpath.exe"
    return environment / "bin" / "vexpath"


def main() -> int:
    wheels = build()
    # Before installing anything: a malformed archive is a defect in what
    # would be published, whether or not this machine's installer objects.
    inspect_archives()
    verify(wheels)
    return 0


if __name__ == "__main__":
    sys.exit(main())
