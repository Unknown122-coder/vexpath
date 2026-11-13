"""Resolve an advisory to the commit that fixed it.

Advisories almost never say which functions are vulnerable, but they almost
always point at the commit that fixed the problem. That commit's diff is the
best available evidence of where the vulnerable logic lived, so finding it is
the first step of symbol extraction.

Nothing here touches the network. Resolution is parsing: a reference URL, a
GIT range, or a repository plus a fixed version. What each tier yields differs
in how much it can be trusted, and that difference carries all the way through
to the confidence on every verdict built from it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from vexpath_core.advisory.coverage import FixReferenceTier, classify_fix_reference
from vexpath_core.enums import Confidence
from vexpath_core.models.advisory import Advisory, RangeType

#: Forge hosts this project will fetch from. Anything else is refused rather
#: than followed, because an advisory reference is attacker-influenced data
#: (see docs/06-threat-model.md).
ALLOWED_HOSTS = frozenset(
    {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht"}
)

_COMMIT_URL = re.compile(
    r"https?://(?:www\.)?(?P<host>[^/]+)/(?P<owner>[^/]+)/(?P<repo>[^/]+)"
    r"/(?:-/)?commits?/(?P<sha>[0-9a-fA-F]{7,40})",
)

_PULL_REQUEST_URL = re.compile(
    r"https?://(?:www\.)?(?P<host>[^/]+)/(?P<owner>[^/]+)/(?P<repo>[^/]+)"
    r"/(?:pull/(?P<pr>\d+)|-/merge_requests/(?P<mr>\d+)|pull-requests/(?P<bb>\d+))",
)

#: Tier to the confidence a symbol extracted through it deserves. A precise
#: commit is strong evidence; a release-tag diff contains everything else that
#: shipped in that release, so it is weak.
TIER_CONFIDENCE: dict[FixReferenceTier, Confidence] = {
    FixReferenceTier.COMMIT: Confidence.HIGH,
    FixReferenceTier.GIT_RANGE: Confidence.HIGH,
    FixReferenceTier.PULL_REQUEST: Confidence.MEDIUM,
    FixReferenceTier.TAG_DERIVABLE: Confidence.LOW,
    FixReferenceTier.NONE: Confidence.LOW,
}


@dataclass(frozen=True, slots=True)
class FixReference:
    """Where to find the change that fixed an advisory."""

    repository: str
    tier: FixReferenceTier
    #: Commit to diff against its parent, when one is known outright.
    commit: str | None = None
    #: Merge request to resolve to a commit, which needs one API call.
    pull_request: int | None = None
    #: Version whose release tag can be diffed, the weakest option.
    fixed_version: str | None = None
    #: The other end of a release diff. When set, ``commit`` is diffed
    #: against this rather than against its own parent: a release tag points
    #: at a release commit, whose parent diff is usually a version bump and
    #: nothing else, so the fix is only visible across the whole range from
    #: the previous release.
    base: str | None = None
    host: str = "github.com"
    owner: str = ""
    name: str = ""

    @property
    def confidence(self) -> Confidence:
        """How much a symbol extracted through this reference deserves."""
        return TIER_CONFIDENCE[self.tier]

    @property
    def is_fetchable(self) -> bool:
        """Whether this reference points somewhere we are willing to fetch."""
        return self.host in ALLOWED_HOSTS and bool(self.repository)

    @property
    def needs_resolution(self) -> bool:
        """Whether an API call is still required to get a commit."""
        return self.commit is None

    @property
    def spans_commits(self) -> bool:
        """Whether the diff runs between two commits rather than from a parent.

        Mechanical: it says how to read the diff, nothing about how much the
        result is worth. Both a release range and a resolved merge request
        span commits.
        """
        return self.base is not None

    @property
    def is_release_diff(self) -> bool:
        """Whether the span is a whole release rather than a fix.

        Semantic, and the two were one property until a merge request could
        also span commits -- at which point a pull request's symbols would
        have been labelled ``tag_diff`` and capped at the size of a typical
        fix commit. A pull request *is* the fix: it deserves neither the label
        nor the cap. A release contains every change made since the last one,
        and deserves both.
        """
        return self.base is not None and self.tier is FixReferenceTier.TAG_DERIVABLE


class UnresolvableFixError(Exception):
    """Raised when an advisory offers nothing to diff."""


def resolve(advisory: Advisory) -> FixReference:
    """Find the best fix reference for an advisory.

    Tried in descending order of trustworthiness, so an advisory carrying both
    a commit link and a derivable tag yields the commit.

    Raises:
        UnresolvableFixError: when the advisory offers nothing usable, or
            points only at a host this project will not fetch from.
    """
    tier = classify_fix_reference(advisory)

    if tier is FixReferenceTier.COMMIT:
        for reference in advisory.references:
            match = _COMMIT_URL.search(reference.url)
            if match is None:
                continue
            found = _from_match(match, tier=tier, commit=match.group("sha"))
            if found.is_fetchable:
                return found

    if tier is FixReferenceTier.GIT_RANGE:
        from_range = _from_git_range(advisory)
        if from_range is not None and from_range.is_fetchable:
            return from_range

    if tier is FixReferenceTier.PULL_REQUEST:
        for reference in advisory.references:
            match = _PULL_REQUEST_URL.search(reference.url)
            if match is None:
                continue
            number = match.group("pr") or match.group("mr") or match.group("bb")
            found = _from_match(match, tier=tier, pull_request=int(number))
            if found.is_fetchable:
                return found

    if tier is FixReferenceTier.TAG_DERIVABLE and advisory.repo_url:
        parts = _split_repository(advisory.repo_url)
        if parts is not None:
            host, owner, name = parts
            fixed = next(
                (version for package in advisory.affected for version in package.fixed_versions),
                None,
            )
            found = FixReference(
                repository=advisory.repo_url,
                tier=tier,
                fixed_version=fixed,
                host=host,
                owner=owner,
                name=name,
            )
            if found.is_fetchable:
                return found

    msg = (
        f"{advisory.id} offers no usable fix reference. Tier was {tier.value}; "
        f"either nothing points at a fix, or everything that does lives on a "
        f"host this project will not fetch from."
    )
    raise UnresolvableFixError(msg)


def _from_match(
    match: re.Match[str],
    *,
    tier: FixReferenceTier,
    commit: str | None = None,
    pull_request: int | None = None,
) -> FixReference:
    host = match.group("host")
    owner = match.group("owner")
    name = match.group("repo").removesuffix(".git")
    return FixReference(
        repository=f"https://{host}/{owner}/{name}",
        tier=tier,
        commit=commit,
        pull_request=pull_request,
        host=host,
        owner=owner,
        name=name,
    )


def _from_git_range(advisory: Advisory) -> FixReference | None:
    """Read a repository and fix commit straight out of a GIT range.

    OSV's GIT ranges carry both, which makes them as good as a commit
    reference and saves a lookup.
    """
    for package in advisory.affected:
        for affected_range in package.ranges:
            if affected_range.type is not RangeType.GIT or not affected_range.repo:
                continue
            fixed = next((event.fixed for event in affected_range.events if event.fixed), None)
            if fixed is None:
                continue
            parts = _split_repository(affected_range.repo)
            if parts is None:
                continue
            host, owner, name = parts
            return FixReference(
                repository=affected_range.repo,
                tier=FixReferenceTier.GIT_RANGE,
                commit=fixed,
                host=host,
                owner=owner,
                name=name,
            )
    return None


def _split_repository(url: str) -> tuple[str, str, str] | None:
    """Split a repository URL into host, owner and name."""
    without_scheme = url.split("://", 1)[-1]
    parts = [part for part in without_scheme.split("/") if part]
    if len(parts) < 3:
        return None
    host = parts[0].removeprefix("www.")
    return host, parts[1], parts[2].removesuffix(".git")


__all__ = [
    "ALLOWED_HOSTS",
    "TIER_CONFIDENCE",
    "FixReference",
    "UnresolvableFixError",
    "resolve",
]
