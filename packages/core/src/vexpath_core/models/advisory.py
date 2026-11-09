"""Advisory model, normalised from OSV and GitHub Security Advisories.

Affected ranges keep the OSV event shape rather than being flattened into
"min version, max version". OSV events describe a timeline of ``introduced``
and ``fixed`` points that can reopen, and flattening them loses vulnerabilities
in packages whose fix was reverted or backported to several branches.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum

from pydantic import AwareDatetime, Field, model_validator

from vexpath_core.enums import Confidence, Severity, SymbolKind, SymbolSource, SymbolsStatus
from vexpath_core.models.common import Base, CvssScore, Reference


class RangeType(StrEnum):
    """OSV range kinds."""

    ECOSYSTEM = "ECOSYSTEM"
    SEMVER = "SEMVER"
    GIT = "GIT"


class RangeEvent(Base):
    """One point on an OSV affected-range timeline.

    Exactly one field is set per event, which is how OSV encodes them.
    """

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> RangeEvent:
        set_fields = [
            f
            for f in (self.introduced, self.fixed, self.last_affected, self.limit)
            if f is not None
        ]
        if len(set_fields) != 1:
            msg = "an OSV range event sets exactly one of introduced/fixed/last_affected/limit"
            raise ValueError(msg)
        return self


class AffectedRange(Base):
    """A range of affected versions, as OSV expresses it."""

    type: RangeType
    #: Repository the range applies to. Required by OSV for GIT ranges and the
    #: most reliable place to find a fix commit.
    repo: str | None = None
    events: tuple[RangeEvent, ...]

    @property
    def fixed_versions(self) -> tuple[str, ...]:
        return tuple(e.fixed for e in self.events if e.fixed is not None)


class AffectedPackage(Base):
    """One package affected by an advisory."""

    ecosystem: str
    name: str
    #: Versionless purl, the key advisory lookups join on.
    purl_base: str
    ranges: tuple[AffectedRange, ...] = ()
    #: Explicit version list, when the advisory enumerates rather than ranges.
    versions: tuple[str, ...] = ()

    @property
    def fixed_versions(self) -> tuple[str, ...]:
        """Every version named as fixing this package, for upgrade advice."""
        seen: dict[str, None] = {}
        for affected_range in self.ranges:
            for version in affected_range.fixed_versions:
                seen.setdefault(version, None)
        return tuple(seen)


class VulnerableSymbol(Base):
    """A symbol whose code the advisory's fix changed.

    This is the target of reachability search. ``confidence`` records how
    directly the fix touched it: a hunk inside a function body is strong
    evidence, a signature-only change is weaker, and a tag-to-tag diff weaker
    still. See ``docs/03-reachability-design.md`` section 3.
    """

    advisory_id: str
    ecosystem: str
    package_name: str
    #: Fully qualified, for example ``requests.adapters.HTTPAdapter.send``.
    symbol: str
    kind: SymbolKind
    source: SymbolSource
    confidence: Confidence
    #: Path in the upstream repository at the fix commit.
    file_path: str | None = None
    fix_commit: str | None = None


class Advisory(Base):
    """A deduplicated vulnerability record."""

    #: Primary identifier, preferring CVE, then GHSA, then the ecosystem's own.
    id: str
    #: Every other identifier this advisory is known by.
    aliases: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss_v3: CvssScore | None = None
    cvss_v4: CvssScore | None = None
    #: Exploit Prediction Scoring System: probability of exploitation in the
    #: next 30 days, refreshed daily.
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    #: Listed in the CISA Known Exploited Vulnerabilities catalogue.
    kev: bool = False
    kev_added_at: date | None = None
    cwe_ids: tuple[str, ...] = ()
    references: tuple[Reference, ...] = ()
    #: Upstream repository, inferred from references or GIT ranges. The entry
    #: point for symbol extraction.
    repo_url: str | None = None
    published_at: AwareDatetime | None = None
    modified_at: AwareDatetime | None = None
    withdrawn_at: AwareDatetime | None = None
    affected: tuple[AffectedPackage, ...] = ()
    symbols: tuple[VulnerableSymbol, ...] = ()
    symbols_status: SymbolsStatus = SymbolsStatus.PENDING
    #: SHA-256 of the normalised source record, for change detection on sync.
    source_sha256: str | None = None

    @property
    def is_withdrawn(self) -> bool:
        return self.withdrawn_at is not None

    @property
    def all_ids(self) -> tuple[str, ...]:
        """The primary identifier followed by every alias."""
        return (self.id, *self.aliases)

    @property
    def is_malicious_package(self) -> bool:
        """True when this record describes malware rather than a vulnerability.

        OSV publishes a malicious-package database alongside its vulnerability
        data, using identifiers prefixed ``MAL-``. The distinction matters more
        than it looks:

        - There is no fix commit, because there is no fix. The remedy is to
          remove the package, not to upgrade it.
        - Reachability analysis is meaningless. The question is not whether the
          malicious code is called, it is whether the package is installed at
          all, because installation alone runs its setup code.

        So these records must never be measured against fix-commit coverage,
        and must never be cleared as unreachable.
        """
        return any(identifier.upper().startswith("MAL-") for identifier in self.all_ids)

    def symbols_for(self, ecosystem: str, package_name: str) -> tuple[VulnerableSymbol, ...]:
        """Vulnerable symbols belonging to one affected package.

        Curated symbols override extracted ones for the same name, because a
        human reviewed them.
        """
        matching = [
            s for s in self.symbols if s.ecosystem == ecosystem and s.package_name == package_name
        ]
        curated = {s.symbol for s in matching if s.source is SymbolSource.CURATED}
        return tuple(
            s for s in matching if s.source is SymbolSource.CURATED or s.symbol not in curated
        )

    def fixed_versions_for(self, ecosystem: str, package_name: str) -> tuple[str, ...]:
        """Versions that fix this advisory for one package."""
        for package in self.affected:
            if package.ecosystem == ecosystem and package.name == package_name:
                return package.fixed_versions
        return ()


class AdvisorySnapshot(Base):
    """An immutable record of the advisory corpus at one point in time.

    Scans store the snapshot identifier they used, which is what allows a
    verdict to be re-derived months later and compared honestly.
    """

    id: str
    created_at: AwareDatetime
    #: Hash over every advisory's ``source_sha256``, sorted.
    content_sha256: str
    ecosystems: tuple[str, ...]
    #: Per ecosystem: total advisories and how many have vulnerable symbols.
    #: Symbol coverage is the metric the product's usefulness rests on.
    counts: dict[str, dict[str, int]] = Field(default_factory=dict)


__all__ = [
    "Advisory",
    "AdvisorySnapshot",
    "AffectedPackage",
    "AffectedRange",
    "RangeEvent",
    "RangeType",
    "VulnerableSymbol",
]
