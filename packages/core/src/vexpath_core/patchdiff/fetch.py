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

import hashlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from packaging.version import InvalidVersion
from packaging.version import Version as Pep440Version

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

#: Python files a release diff may touch before it is refused.
#:
#: Much smaller than the per-commit cap, and for a different reason. That one
#: guards against a vendored dependency landing in one commit; this one
#: guards against the thing a release diff *usually* is. A release contains
#: every change made since the last one, so taking its symbols means claiming
#: the fix touched all of them -- and a corpus where jinja2 has four hundred
#: vulnerable symbols makes every project that imports jinja2 reachable,
#: which is indistinguishable from having no reachability analysis at all.
#:
#: Forty is a release small enough that its contents are plausibly about one
#: thing. Above that the advisory stays unextracted, which is an honest
#: "nobody could look" rather than a confident wrong answer.
MAX_FILES_PER_TAG_DIFF = 40

#: Symbols a release diff may name before it is refused.
#:
#: The file cap is not enough, which measuring showed rather than argued: a
#: release touching thirty files named 248 symbols for one package. Across the
#: corpus a fix commit names 4 symbols at the median and 22 at the ninetieth
#: percentile; a release diff named 25 at the median and 104 at the
#: ninetieth. Six times noisier in the middle and five times at the tail.
#:
#: So a release diff may name no more symbols than a typical fix commit does.
#: Beyond that it has stopped being evidence about a fix and become an
#: inventory of a package, and an advisory listing a hundred functions makes
#: every project importing that package reachable -- a confident wrong answer
#: in place of an honest "nobody could look".
MAX_SYMBOLS_PER_TAG_DIFF = 25

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

    def resolve_release_range(
        self, repository: str, fixed_version: str, *, affected_versions: Sequence[str] = ()
    ) -> tuple[str, str] | None:
        """Return ``(previous_commit, fixed_commit)``, or None if unresolved.

        Part of the protocol because the pipeline cannot extract from a
        version number: an advisory that names only "fixed in 2.11.3" needs
        this call before there is anything to diff.
        """
        ...

    def resolve_pull_request(self, repository: str, number: int) -> tuple[str, str] | None:
        """Return ``(base_commit, head_commit)`` for a merge request.

        No forge API: the hosts this fetches from advertise the refs over
        plain git, so this needs no token and has no hourly limit.
        """
        ...


class GitCommitSource:
    """Fetch a commit with the git binary.

    Never checks out a working tree: a bare fetch plus ``git show`` reads blobs
    without writing any file from the repository to disk, so nothing in the
    fetched repository can run.

    With a ``cache_root``, one bare repository is kept per upstream and reused.
    Several advisories often name commits in the same repository, and a
    corpus-wide extraction run meets that case constantly: the second commit
    from a repository costs an incremental fetch into an existing object store
    rather than another clone. Without a ``cache_root`` each fetch gets a
    throwaway directory, which is right for a one-off.
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
        if cache_root is not None:
            # Created once, here, rather than on first use. A cache directory
            # that does not exist yet is the ordinary state of a fresh
            # deployment, and discovering it one advisory at a time spends
            # their retry budget on a configuration detail.
            try:
                cache_root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                msg = f"cache root {cache_root} could not be created: {exc}"
                raise FetchError(msg) from exc

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

        if self._cache_root is None:
            with tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                self._prepare(workspace, reference.repository)
                self._fetch_commit(workspace, reference.commit)
                if reference.base is not None:
                    # Both ends, or the diff has nothing to measure from.
                    self._fetch_commit(workspace, reference.base)
                return self._read(workspace, reference)

        workspace = self._cache_root / _repository_slug(reference.repository)
        try:
            self._prepare(workspace, reference.repository)
            self._fetch_commit(workspace, reference.commit)
            return self._read(workspace, reference)
        except FetchError:
            # A reused repository can be left unusable by an interrupted fetch,
            # and every later advisory sharing it would then fail for a reason
            # that has nothing to do with them. Discard it so the next attempt
            # starts clean, and report this one as the failure it is.
            shutil.rmtree(workspace, ignore_errors=True)
            raise

    def _prepare(self, workspace: Path, repository: str) -> None:
        """Make ``workspace`` a bare repository pointing at ``repository``."""
        workspace.mkdir(parents=True, exist_ok=True)
        if not (workspace / "HEAD").is_file():
            self._run(["init", "--quiet", "--bare"], workspace)
        # set-url rather than add, so a reused directory whose remote is
        # already configured is not an error. The URL is re-set every time
        # because two repositories can hash to one slug only if they are the
        # same URL, but a redirect may have changed it upstream.
        self._run(["remote", "remove", "origin"], workspace, allow_failure=True)
        self._run(["remote", "add", "origin", repository], workspace)

    def _fetch_commit(self, workspace: Path, commit: str) -> None:
        """Fetch one commit and its parent, without their file contents.

        ``--filter=blob:none`` is what makes this usable on a large
        repository. A depth-2 fetch still transfers every blob in both trees,
        which for cryptography or feast is most of the repository and timed out
        at five minutes when measured. With the filter, only commits and trees
        arrive, and the handful of file contents the diff actually names are
        fetched on demand by ``git show``.

        Servers that do not offer partial clone refuse the filter rather than
        ignoring it, so the plain fetch is tried next.
        """
        filtered = self._run(
            [
                "fetch",
                "--quiet",
                "--filter=blob:none",
                f"--depth={FETCH_DEPTH}",
                "origin",
                commit,
            ],
            workspace,
            timeout=self._fetch_timeout,
            allow_failure=True,
        )
        if filtered is not None:
            return
        self._run(
            ["fetch", "--quiet", f"--depth={FETCH_DEPTH}", "origin", commit],
            workspace,
            timeout=self._fetch_timeout,
        )

    def resolve_tag(self, repository: str, tag_candidates: Sequence[str]) -> str | None:
        """Return the commit a release tag points at, or None if none matches.

        One ``ls-remote`` call, no clone. This is what turns a reference that
        names only a fixed version into one that names a commit, and over a
        real batch that was two advisories in five.

        Candidates are tried in order because projects spell the same release
        differently: ``1.2.3``, ``v1.2.3``, ``release-1.2.3``. Asking for all
        of them in one call and picking the first match is cheaper than a call
        per spelling.
        """
        if repository_host(repository) not in ALLOWED_HOSTS:
            msg = f"refusing to contact {repository}, which is not on the allow-list"
            raise FetchError(msg)

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            listing = self._run(
                ["ls-remote", "--tags", "--refs", repository],
                workspace,
                timeout=self._fetch_timeout,
                allow_failure=True,
            )
        if not listing:
            return None

        tags: dict[str, str] = {}
        for line in listing.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].startswith("refs/tags/"):
                tags[parts[1].removeprefix("refs/tags/")] = parts[0]

        for candidate in tag_candidates:
            if candidate in tags:
                return tags[candidate]
        return None

    def resolve_release_range(
        self, repository: str, fixed_version: str, *, affected_versions: Sequence[str] = ()
    ) -> tuple[str, str] | None:
        """Return ``(previous_commit, fixed_commit)`` for a fixed version.

        The missing half of tag resolution. An advisory that names only "fixed
        in 2.11.3" has no commit to diff, and 2,441 PyPI advisories -- most of
        what is left after fix commits are exhausted -- are exactly that.

        One ``ls-remote``, then the work is version arithmetic: find the tag
        for the fixed release, and the tag immediately below it, because the
        fix is somewhere between them. Tags are ordered by PEP 440 rather than
        by string, so 2.11.10 sorts above 2.11.9, and pre-releases are skipped
        -- a release candidate is not the previous release.

        Returns None when either end cannot be found, which is a reference
        that stays unresolved rather than a guess.
        """
        if repository_host(repository) not in ALLOWED_HOSTS:
            msg = f"refusing to contact {repository}, which is not on the allow-list"
            raise FetchError(msg)

        tags = self._list_tags(repository)
        if not tags:
            return None

        fixed_tag = _match_tag(tags, fixed_version)
        if fixed_tag is None:
            return None

        previous_tag = _previous_release(tags, fixed_tag[0], affected_versions=affected_versions)
        if previous_tag is None:
            return None
        return previous_tag[1], fixed_tag[1]

    def resolve_pull_request(self, repository: str, number: int) -> tuple[str, str] | None:
        """Turn a merge request into the pair of commits that bracket it.

        1,343 PyPI advisories -- everything left after fix commits and release
        tags -- point at a pull request and nothing else. There is no API call
        here and no token: GitHub and the other hosts advertise
        ``refs/pull/N/head`` and ``refs/pull/N/merge`` over plain git, so this
        is two fetches at most and no rate limit at all.

        ``/merge`` is preferred and rarely there. It is the test merge the
        forge builds, whose first parent is the base and second is the branch,
        so diffing between them is exactly the pull request and nothing else.
        Measured across three large repositories, only 16% to 38% of pull
        requests still have it -- it is kept for open ones.

        ``/head`` is the fallback and is kept for ever. Its final commit is
        diffed against its parent, which under-reports a branch of several
        commits: the earlier ones are missed. That is the safe direction for
        this tool, because a missed symbol produces "nobody could look" while
        an invented one produces a confident wrong answer.

        A ``/head`` that is itself a merge commit is refused rather than
        diffed. Branches routinely merge the base back into themselves, and
        diffing such a commit against its first parent attributes everything
        the other branch brought to this fix -- hundreds of files that have
        nothing to do with it.
        """
        if repository_host(repository) not in ALLOWED_HOSTS:
            msg = f"refusing to contact {repository}, which is not on the allow-list"
            raise FetchError(msg)

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            self._prepare(workspace, repository)

            for suffix in ("merge", "head"):
                reference = f"{_pull_ref_prefix(repository)}/{number}/{suffix}"
                fetched = self._run(
                    [
                        "fetch",
                        "--quiet",
                        "--depth=2",
                        "--filter=blob:none",
                        repository,
                        reference,
                    ],
                    workspace,
                    timeout=self._fetch_timeout,
                    allow_failure=True,
                )
                if fetched is None:
                    continue

                parents = (
                    self._run(
                        ["rev-list", "--parents", "-n", "1", "FETCH_HEAD"],
                        workspace,
                        allow_failure=True,
                    )
                    or ""
                ).split()
                if len(parents) < 2:
                    # A root commit, or the rev-list failed. Nothing to diff
                    # against either way.
                    continue
                head, ancestors = parents[0], parents[1:]

                if suffix == "merge":
                    if len(ancestors) < 2:
                        continue
                    return ancestors[0], ancestors[1]

                if len(ancestors) != 1:
                    # The branch tip is a merge. See the docstring.
                    continue
                return ancestors[0], head

        return None

    def _list_tags(self, repository: str) -> dict[str, str]:
        """Every tag the remote advertises, as name to commit."""
        with tempfile.TemporaryDirectory() as directory:
            listing = self._run(
                ["ls-remote", "--tags", "--refs", repository],
                Path(directory),
                timeout=self._fetch_timeout,
                allow_failure=True,
            )
        if not listing:
            return {}
        tags: dict[str, str] = {}
        for line in listing.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].startswith("refs/tags/"):
                tags[parts[1].removeprefix("refs/tags/")] = parts[0]
        return tags

    def _read(self, workspace: Path, reference: FixReference) -> CommitDiff:
        commit = reference.commit or "FETCH_HEAD"
        # A release range diffs from the previous release rather than from
        # this commit's parent. A release commit's parent diff is usually a
        # version bump and a changelog entry, so diffing it would find the
        # fix in approximately none of these advisories.
        parent = reference.base or f"{commit}^"
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
        # A commit whose parent is unreachable at this depth produces no diff
        # rather than an error, and so does a failed diff. Both mean there is
        # nothing to read, which the caller reports as no symbols found.
        diff = diff or ""
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
    ) -> str | None:
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
                # None, not "": a quiet command that succeeded also prints
                # nothing, and a caller choosing a fallback has to tell the two
                # apart.
                return None
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            first = detail[0] if detail else "no output"
            msg = f"git {arguments[0]} failed: {first}"
            raise FetchError(msg)
        return completed.stdout


def repository_host(repository: str) -> str:
    """The host part of a repository URL, for the allow-list check."""
    without_scheme = repository.removeprefix("https://").removeprefix("http://")
    return without_scheme.split("/", 1)[0].lower()


#: Where each host keeps its merge-request refs.
#:
#: GitHub and the Gitea-shaped hosts use ``refs/pull``; GitLab calls the same
#: thing a merge request and uses ``refs/merge-requests``. Both are advertised
#: over plain git, which is what lets this work without a forge API.
_PULL_REF_PREFIXES = {
    "gitlab.com": "refs/merge-requests",
}
_DEFAULT_PULL_REF_PREFIX = "refs/pull"


def _pull_ref_prefix(repository: str) -> str:
    return _PULL_REF_PREFIXES.get(repository_host(repository), _DEFAULT_PULL_REF_PREFIX)


#: How projects spell the same release. Tried in order.
TAG_SPELLINGS: tuple[str, ...] = ("{version}", "v{version}", "release-{version}", "rel-{version}")


def _match_tag(tags: dict[str, str], version: str) -> tuple[str, str] | None:
    """The tag naming ``version``, trying the spellings projects use."""
    for template in TAG_SPELLINGS:
        candidate = template.format(version=version)
        if candidate in tags:
            return candidate, tags[candidate]
    return None


def _previous_release(
    tags: dict[str, str], fixed_tag: str, *, affected_versions: Sequence[str] = ()
) -> tuple[str, str] | None:
    """The release immediately below ``fixed_tag``, by PEP 440 order.

    When the advisory lists the versions it affects, the highest of those is
    preferred: it is the last release known to be vulnerable, so the span to
    the fix is exactly the window the fix closed. Falling back to "whatever
    tag sorts next" is a guess, but a narrow one, and narrower than the
    alternative of not looking.
    """
    parsed: list[tuple[Pep440Version, str]] = []
    for name in tags:
        version = _version_of(name)
        if version is None or version.is_prerelease:
            # A release candidate is not the previous release, and diffing
            # from one would attribute its changes to the fix.
            continue
        parsed.append((version, name))
    if not parsed:
        return None

    fixed_version = _version_of(fixed_tag)
    if fixed_version is None:
        return None

    for candidate in sorted(affected_versions, key=_sort_key, reverse=True):
        matched = _match_tag(tags, candidate)
        if matched is not None and (_version_of(matched[0]) or fixed_version) < fixed_version:
            return matched

    below = [entry for entry in parsed if entry[0] < fixed_version]
    if not below:
        return None
    name = max(below)[1]
    return name, tags[name]


def _version_of(tag: str) -> Pep440Version | None:
    """Parse a tag as a version, or None if it is not one."""
    text = tag
    for prefix in ("release-", "rel-", "v"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    try:
        return Pep440Version(text)
    except InvalidVersion:
        return None


def _sort_key(version: str) -> Pep440Version:
    parsed = _version_of(version)
    return parsed if parsed is not None else Pep440Version("0")


def _repository_slug(repository: str) -> str:
    """A filesystem-safe directory name for one repository URL.

    The readable part is kept for someone looking at the cache directory, and
    a hash of the full URL is appended so two upstreams that differ only in a
    stripped character cannot share an object store.
    """
    # Normalised before hashing, so the same upstream written two ways shares
    # one object store instead of being cloned twice.
    normalised = (
        repository.strip()
        .lower()
        .removeprefix("https://")
        .removeprefix("http://")
        .removesuffix("/")
        .removesuffix(".git")
    )
    readable = "".join(
        character if character.isalnum() or character in "-_." else "-" for character in normalised
    ).strip("-")[:60]
    digest = hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:12]
    return f"{readable}-{digest}" if readable else digest


@dataclass(frozen=True, slots=True)
class RecordedCommitSource:
    """A commit source backed by diffs recorded on disk.

    Used by the tests and by the benchmark, so extraction can be exercised
    against real commits with no network and no variation between runs.
    """

    diffs: dict[str, CommitDiff]
    #: Release tag to commit, for resolving a version to a range. Empty by
    #: default, which is a repository that advertises no tags -- the same
    #: answer a project without releases gives.
    tags: dict[str, str] = field(default_factory=dict)

    def fetch(self, reference: FixReference) -> CommitDiff:
        key = reference.commit or reference.repository
        if key not in self.diffs:
            msg = f"no recorded diff for {key}"
            raise FetchError(msg)
        return self.diffs[key]

    #: Merge request number to the pair of commits bracketing it. Empty by
    #: default, which is a forge that advertises no pull refs.
    pull_requests: dict[int, tuple[str, str]] = field(default_factory=dict)

    def resolve_pull_request(self, repository: str, number: int) -> tuple[str, str] | None:
        del repository
        return self.pull_requests.get(number)

    def resolve_release_range(
        self, repository: str, fixed_version: str, *, affected_versions: Sequence[str] = ()
    ) -> tuple[str, str] | None:
        """The same version arithmetic as the real source, on recorded tags."""
        fixed = _match_tag(self.tags, fixed_version)
        if fixed is None:
            return None
        previous = _previous_release(self.tags, fixed[0], affected_versions=affected_versions)
        if previous is None:
            return None
        return previous[1], fixed[1]


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
