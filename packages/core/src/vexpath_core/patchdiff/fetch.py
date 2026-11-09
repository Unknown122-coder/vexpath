"""Fetch a commit's diff and the file contents around it.

The only part of symbol extraction that needs the network, isolated so
everything that decides what a symbol *is* can be tested against recorded
diffs.

Fetching uses git rather than a forge API, for three reasons. One shallow fetch
serves every file in a commit, where an API costs a request per file and a rate
limit. Git works against any forge rather than one. And a fetch never checks
out a working tree, so no code from the repository is ever executed.

The safety measures are not incidental. A repository URL comes from advisory
data, which is attacker-influenced, so hosts are checked against an allow-list
before anything runs, hooks are disabled, credential prompting is off, and the
process is bounded in both time and output size.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from vexpath_core.patchdiff.references import ALLOWED_HOSTS, FixReference
from vexpath_core.patchdiff.unidiff import FileDiff, python_files

#: A commit is fetched with its parent and nothing else.
FETCH_DEPTH = 2

#: Caps. A fix commit is small; anything near these limits is a vendored
#: dependency update or a repository import, and is not worth the time.
#: Generous, because a shallow fetch of one commit from a very large
#: repository still transfers a sizeable pack. Measured against real
#: advisories, two minutes was not enough for the largest projects.
FETCH_TIMEOUT_SECONDS = 300
DIFF_TIMEOUT_SECONDS = 30
MAX_DIFF_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES_PER_COMMIT = 200

#: Environment for every git call. Hooks off, no prompting, no system or user
#: configuration, so a developer's own git settings cannot change what a scan
#: concludes.
_GIT_ENVIRONMENT = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_ALLOW_PROTOCOL": "https",
    "HOME": "",
}


class FetchError(Exception):
    """Raised when a commit cannot be fetched."""


@dataclass(frozen=True, slots=True)
class CommitDiff:
    """A commit's changed Python files, with their sources on both sides."""

    commit: str
    repository: str
    #: Each changed file, with its content after the commit and before it.
    #: Either may be None, for a file the commit added or deleted.
    files: tuple[tuple[FileDiff, str | None, str | None], ...] = ()
    #: Repository build configuration at the commit, for mapping paths to
    #: module names. Read as data, never executed.
    pyproject: str | None = None
    setup_cfg: str | None = None
    #: What was skipped, and why.
    notes: tuple[str, ...] = field(default=())


class CommitSource(Protocol):
    """Where a commit's diff comes from.

    Implemented by `GitCommitSource` for real use and by a recorded double in
    the tests, which is what keeps extraction testable without the network.
    """

    def fetch(self, reference: FixReference) -> CommitDiff:
        """Return the diff for a reference's commit.

        Raises:
            FetchError: if the commit cannot be retrieved.
        """
        ...


class GitCommitSource:
    """Fetch a commit with the git binary.

    Never checks out a working tree: a bare fetch plus ``git show`` reads blobs
    without writing any file from the repository to disk, so nothing in the
    fetched repository can run.
    """

    __slots__ = ("_cache_root", "_fetch_timeout", "_git")

    def __init__(
        self,
        *,
        git: str | None = None,
        cache_root: Path | None = None,
        fetch_timeout: int = FETCH_TIMEOUT_SECONDS,
    ) -> None:
        resolved = git or shutil.which("git")
        if resolved is None:
            msg = "git was not found on PATH, and symbol extraction needs it"
            raise FetchError(msg)
        self._git = resolved
        self._cache_root = cache_root
        self._fetch_timeout = fetch_timeout

    def fetch(self, reference: FixReference) -> CommitDiff:
        if reference.commit is None:
            msg = (
                f"{reference.repository} reference has no commit to fetch; resolve "
                f"the pull request or release tag first"
            )
            raise FetchError(msg)
        if reference.host not in ALLOWED_HOSTS:
            # A repository URL comes from advisory data, which is
            # attacker-influenced. Refuse rather than follow.
            msg = f"refusing to fetch from {reference.host}, which is not on the allow-list"
            raise FetchError(msg)

        with tempfile.TemporaryDirectory(dir=self._cache_root) as directory:
            workspace = Path(directory)
            self._run(["init", "--quiet", "--bare"], workspace)
            self._run(["remote", "add", "origin", reference.repository], workspace)
            self._run(
                ["fetch", "--quiet", f"--depth={FETCH_DEPTH}", "origin", reference.commit],
                workspace,
                timeout=self._fetch_timeout,
            )
            return self._read(workspace, reference)

    def _read(self, workspace: Path, reference: FixReference) -> CommitDiff:
        commit = reference.commit or "FETCH_HEAD"
        parent = f"{commit}^"
        notes: list[str] = []

        diff = self._run(
            [
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "-M",
                parent,
                commit,
                "--",
                "*.py",
            ],
            workspace,
            timeout=DIFF_TIMEOUT_SECONDS,
            allow_failure=True,
        )
        if len(diff) > MAX_DIFF_BYTES:
            notes.append(
                f"the diff is {len(diff)} bytes, above the {MAX_DIFF_BYTES} byte "
                f"limit, and was truncated"
            )
            diff = diff[:MAX_DIFF_BYTES]

        files: list[tuple[FileDiff, str | None, str | None]] = []
        for index, file_diff in enumerate(python_files(diff)):
            if index >= MAX_FILES_PER_COMMIT:
                notes.append(
                    f"the commit touches more than {MAX_FILES_PER_COMMIT} Python "
                    f"files, so the rest were skipped"
                )
                break
            post = (
                None
                if file_diff.is_deleted_file or file_diff.new_path is None
                else self._show(workspace, commit, file_diff.new_path)
            )
            pre = (
                None
                if file_diff.is_new_file or file_diff.old_path is None
                else self._show(workspace, parent, file_diff.old_path)
            )
            files.append((file_diff, post, pre))

        return CommitDiff(
            commit=commit,
            repository=reference.repository,
            files=tuple(files),
            pyproject=self._show(workspace, commit, "pyproject.toml"),
            setup_cfg=self._show(workspace, commit, "setup.cfg"),
            notes=tuple(notes),
        )

    def _show(self, workspace: Path, revision: str, path: str) -> str | None:
        """Read one file at one revision, or None if it is not there."""
        content = self._run(
            ["show", f"{revision}:{path}"],
            workspace,
            timeout=DIFF_TIMEOUT_SECONDS,
            allow_failure=True,
        )
        if not content:
            return None
        if len(content) > MAX_FILE_BYTES:
            return None
        return content

    def _run(
        self,
        arguments: Sequence[str],
        workspace: Path,
        *,
        timeout: int = DIFF_TIMEOUT_SECONDS,
        allow_failure: bool = False,
    ) -> str:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed binary, no shell
                [self._git, *arguments],
                cwd=workspace,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                env={**os.environ, **_GIT_ENVIRONMENT},
            )
        except subprocess.TimeoutExpired as exc:
            msg = f"git {arguments[0]} timed out after {timeout}s"
            raise FetchError(msg) from exc
        except OSError as exc:
            msg = f"git {arguments[0]} could not be run: {exc}"
            raise FetchError(msg) from exc

        if completed.returncode != 0:
            if allow_failure:
                return ""
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            first = detail[0] if detail else "no output"
            msg = f"git {arguments[0]} failed: {first}"
            raise FetchError(msg)
        return completed.stdout


@dataclass(frozen=True, slots=True)
class RecordedCommitSource:
    """A commit source backed by diffs recorded on disk.

    Used by the tests and by the benchmark, so extraction can be exercised
    against real commits with no network and no variation between runs.
    """

    diffs: dict[str, CommitDiff]

    def fetch(self, reference: FixReference) -> CommitDiff:
        key = reference.commit or reference.repository
        if key not in self.diffs:
            msg = f"no recorded diff for {key}"
            raise FetchError(msg)
        return self.diffs[key]


__all__ = [
    "DIFF_TIMEOUT_SECONDS",
    "FETCH_DEPTH",
    "FETCH_TIMEOUT_SECONDS",
    "MAX_DIFF_BYTES",
    "MAX_FILES_PER_COMMIT",
    "MAX_FILE_BYTES",
    "CommitDiff",
    "CommitSource",
    "FetchError",
    "GitCommitSource",
    "RecordedCommitSource",
]
