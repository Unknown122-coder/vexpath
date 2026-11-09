"""Measure whether reachability analysis is possible at all.

Reachability needs to know which functions an advisory's fix changed. For one
ecosystem, Go, OSV publishes those symbols outright. For every other ecosystem,
including PyPI, it does not: they have to be recovered by diffing the commit
that fixed the issue.

So there are two different numbers, and conflating them would be misleading:

**Symbol coverage** is the share of advisories that already name their
vulnerable symbols. For PyPI this is zero, and will stay zero, because OSV
carries no such field for it. A zero here means "nothing was handed to us", not
"nothing is possible".

**Fix-reference coverage** is the share of advisories from which a fix commit
can be recovered. This is the number that decides whether the call-graph engine
is worth building, because it caps how many findings reachability can ever
speak to. It is reported by tier, because the tiers differ in how much trust
the resulting symbols deserve:

| Tier | What it means | Symbol confidence it supports |
|---|---|---|
| `commit` | A reference points directly at a fix commit | high |
| `git_range` | A GIT range names the repository and a fixed commit | high |
| `pull_request` | A reference points at a merge request, resolvable to a commit | medium |
| `tag_derivable` | Repository and fixed version are known, so release tags can be diffed | low |
| `none` | Nothing to work from | none |
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from vexpath_core.models.advisory import Advisory, RangeType

#: Forge URLs that identify a single commit.
_COMMIT_URL = re.compile(
    r"https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)"
    r"/[^/]+/[^/]+/(?:-/)?commits?/[0-9a-f]{7,40}",
    re.IGNORECASE,
)

#: Forge URLs that identify a merge request, which resolves to a commit with
#: one extra API call.
_PULL_REQUEST_URL = re.compile(
    r"https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)"
    r"/[^/]+/[^/]+/(?:pull/\d+|-/merge_requests/\d+|pull-requests/\d+)",
    re.IGNORECASE,
)


class FixReferenceTier(StrEnum):
    """How a fix commit can be recovered for an advisory, best first."""

    COMMIT = "commit"
    GIT_RANGE = "git_range"
    PULL_REQUEST = "pull_request"
    TAG_DERIVABLE = "tag_derivable"
    NONE = "none"

    @property
    def is_usable(self) -> bool:
        """Whether symbol extraction can start from this tier at all."""
        return self is not FixReferenceTier.NONE

    @property
    def rank(self) -> int:
        return _TIER_RANK[self]


_TIER_RANK: dict[FixReferenceTier, int] = {
    FixReferenceTier.COMMIT: 4,
    FixReferenceTier.GIT_RANGE: 3,
    FixReferenceTier.PULL_REQUEST: 2,
    FixReferenceTier.TAG_DERIVABLE: 1,
    FixReferenceTier.NONE: 0,
}


def classify_fix_reference(advisory: Advisory) -> FixReferenceTier:
    """Return the best tier from which this advisory's fix can be recovered.

    Checked in descending order of trustworthiness, so an advisory with both a
    commit reference and a derivable tag reports the commit.
    """
    urls = [reference.url for reference in advisory.references]

    if any(_COMMIT_URL.search(url) for url in urls):
        return FixReferenceTier.COMMIT

    for package in advisory.affected:
        for affected_range in package.ranges:
            # A GIT range's fixed event is itself a commit identifier, so a
            # range that names both a repository and a fix is as good as a
            # direct commit reference.
            if (
                affected_range.type is RangeType.GIT
                and affected_range.repo
                and any(event.fixed for event in affected_range.events)
            ):
                return FixReferenceTier.GIT_RANGE

    if any(_PULL_REQUEST_URL.search(url) for url in urls):
        return FixReferenceTier.PULL_REQUEST

    # Diffing the fixed release tag against the last affected one needs both a
    # repository and a fixed version. It is the weakest tier because a release
    # diff contains everything else that shipped in it.
    has_fixed_version = any(package.fixed_versions for package in advisory.affected)
    if advisory.repo_url and has_fixed_version:
        return FixReferenceTier.TAG_DERIVABLE

    return FixReferenceTier.NONE


@dataclass(frozen=True, slots=True)
class EcosystemCoverage:
    """What can be analysed for one ecosystem.

    ``advisories`` counts only the records reachability analysis could apply
    to. Two kinds are excluded and counted separately, because including
    either would misreport what the analysis can do:

    *Withdrawn* records never produce a finding at all.

    *Malicious packages* have no fix commit because there is no fix, and
    reachability is the wrong question for them: installing malware runs it.
    They dominate the PyPI corpus by count, so leaving them in the denominator
    understates fix-commit coverage by a factor of nearly three.
    """

    ecosystem: str
    advisories: int
    withdrawn: int
    malicious: int
    with_symbols: int
    tiers: dict[FixReferenceTier, int] = field(default_factory=dict)

    @property
    def total_records(self) -> int:
        """Every record naming this ecosystem, including the excluded kinds."""
        return self.advisories + self.withdrawn + self.malicious

    @property
    def symbol_coverage(self) -> float:
        """Share of advisories that already name their vulnerable symbols."""
        return self.with_symbols / self.advisories if self.advisories else 0.0

    @property
    def usable_fix_references(self) -> int:
        return sum(count for tier, count in self.tiers.items() if tier.is_usable)

    @property
    def fix_reference_coverage(self) -> float:
        """Share of advisories whose fix commit can be recovered.

        The ceiling on what reachability analysis can ever decide for this
        ecosystem.
        """
        return self.usable_fix_references / self.advisories if self.advisories else 0.0

    @property
    def high_confidence_fix_references(self) -> int:
        """Advisories whose fix resolves to an exact commit."""
        return self.tiers.get(FixReferenceTier.COMMIT, 0) + self.tiers.get(
            FixReferenceTier.GIT_RANGE, 0
        )

    @property
    def high_confidence_coverage(self) -> float:
        return self.high_confidence_fix_references / self.advisories if self.advisories else 0.0


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """What a whole corpus can support."""

    snapshot_id: str | None
    advisories: int
    ecosystems: tuple[EcosystemCoverage, ...]
    #: Records excluded from the reachability denominators, and why.
    withdrawn: int = 0
    malicious: int = 0

    def for_ecosystem(self, ecosystem: str) -> EcosystemCoverage | None:
        return next((entry for entry in self.ecosystems if entry.ecosystem == ecosystem), None)


def measure(advisories: Sequence[Advisory], *, snapshot_id: str | None = None) -> CoverageReport:
    """Measure what a corpus can support, per ecosystem.

    Withdrawn advisories are counted separately and excluded from the
    denominators, because they never produce a finding and including them would
    flatter every percentage.
    """
    totals: dict[str, dict[str, int]] = {}
    tiers: dict[str, dict[FixReferenceTier, int]] = {}

    for advisory in advisories:
        ecosystems = {package.ecosystem for package in advisory.affected}
        for ecosystem in ecosystems:
            bucket = totals.setdefault(
                ecosystem,
                {"advisories": 0, "withdrawn": 0, "malicious": 0, "with_symbols": 0},
            )
            if advisory.is_withdrawn:
                bucket["withdrawn"] += 1
                continue
            if advisory.is_malicious_package:
                # No fix exists to diff, and reachability is the wrong
                # question: installing malware runs it.
                bucket["malicious"] += 1
                continue
            bucket["advisories"] += 1
            if advisory.symbols:
                bucket["with_symbols"] += 1
            per_tier = tiers.setdefault(ecosystem, {})
            tier = classify_fix_reference(advisory)
            per_tier[tier] = per_tier.get(tier, 0) + 1

    entries = tuple(
        EcosystemCoverage(
            ecosystem=ecosystem,
            advisories=counts["advisories"],
            withdrawn=counts["withdrawn"],
            malicious=counts["malicious"],
            with_symbols=counts["with_symbols"],
            tiers=dict(tiers.get(ecosystem, {})),
        )
        for ecosystem, counts in sorted(totals.items())
    )

    analysable = sum(
        1
        for advisory in advisories
        if not advisory.is_withdrawn and not advisory.is_malicious_package
    )
    return CoverageReport(
        snapshot_id=snapshot_id,
        advisories=analysable,
        ecosystems=entries,
        withdrawn=sum(1 for advisory in advisories if advisory.is_withdrawn),
        malicious=sum(
            1
            for advisory in advisories
            if advisory.is_malicious_package and not advisory.is_withdrawn
        ),
    )


__all__ = [
    "CoverageReport",
    "EcosystemCoverage",
    "FixReferenceTier",
    "classify_fix_reference",
    "measure",
]
