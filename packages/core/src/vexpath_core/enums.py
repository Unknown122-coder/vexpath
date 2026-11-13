"""Closed vocabularies used across the platform.

Every value that appears in the database, the API, the results JSON and the VEX
output is defined once here. Where a standard already fixes the spelling
(OpenVEX statuses and justifications, OSV ecosystem names, CycloneDX analysis
states) the standard's spelling wins, even when it is inconsistent with the
rest of the codebase.
"""

from __future__ import annotations

from enum import StrEnum

# ---------------------------------------------------------------------------
# Ecosystems
# ---------------------------------------------------------------------------

#: Canonical OSV ecosystem spellings, keyed by a lowercase lookup form. OSV is
#: case-sensitive and inconsistent ("PyPI", "npm", "crates.io"), so inputs are
#: normalised through this table rather than by naive casing.
_ECOSYSTEM_CANONICAL: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "rubygems": "RubyGems",
    "crates.io": "crates.io",
    "cargo": "crates.io",
    "hex": "Hex",
    "pub": "Pub",
    "cran": "CRAN",
    "swifturl": "SwiftURL",
    "conan": "ConanCenter",
    "conancenter": "ConanCenter",
    "hackage": "Hackage",
}

#: purl type for each OSV ecosystem. purl and OSV disagree on several names,
#: so the mapping is explicit in both directions.
_ECOSYSTEM_TO_PURL_TYPE: dict[str, str] = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "Maven": "maven",
    "NuGet": "nuget",
    "Packagist": "composer",
    "RubyGems": "gem",
    "crates.io": "cargo",
    "Hex": "hex",
    "Pub": "pub",
    "CRAN": "cran",
    "SwiftURL": "swift",
    "ConanCenter": "conan",
    "Hackage": "hackage",
}

_PURL_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    purl_type: ecosystem for ecosystem, purl_type in _ECOSYSTEM_TO_PURL_TYPE.items()
}

#: Ecosystems for which reachability analysis is implemented. Everything else
#: gets matching, VEX, attestation and policy, with findings reported as
#: ``symbols_unknown`` / ``ecosystem_unsupported`` (ADR-0012).
REACHABILITY_ECOSYSTEMS: frozenset[str] = frozenset({"PyPI"})

#: Ecosystems whose lockfiles this project parses natively (ADR-0009).
NATIVE_LOCKFILE_ECOSYSTEMS: frozenset[str] = frozenset({"PyPI", "npm"})


def canonical_ecosystem(value: str) -> str:
    """Return the OSV spelling of an ecosystem name.

    Unknown ecosystems are returned stripped but otherwise untouched: OSV adds
    new ones regularly and refusing to carry an unrecognised name would discard
    real data from a valid SBOM.
    """
    return _ECOSYSTEM_CANONICAL.get(value.strip().lower(), value.strip())


def ecosystem_to_purl_type(ecosystem: str) -> str:
    """Return the purl type for an OSV ecosystem name."""
    canonical = canonical_ecosystem(ecosystem)
    return _ECOSYSTEM_TO_PURL_TYPE.get(canonical, canonical.lower())


def purl_type_to_ecosystem(purl_type: str) -> str:
    """Return the OSV ecosystem name for a purl type."""
    lowered = purl_type.strip().lower()
    return _PURL_TYPE_TO_ECOSYSTEM.get(lowered, canonical_ecosystem(lowered))


def supports_reachability(ecosystem: str) -> bool:
    """Return True if reachability analysis is implemented for this ecosystem."""
    return canonical_ecosystem(ecosystem) in REACHABILITY_ECOSYSTEMS


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """Normalised severity label.

    Derived from CVSS v4 when present, then CVSS v3, then the source's own
    label. ``UNKNOWN`` means the advisory carried no usable severity, which is
    different from ``NONE`` (scored, and scored at zero).
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        """Ordering for policy comparisons. Higher means more severe.

        ``UNKNOWN`` ranks above ``NONE`` and below ``LOW``: an unscored
        advisory deserves more attention than one scored harmless, but should
        not outrank a real low finding.
        """
        return _SEVERITY_RANK[self]

    @classmethod
    def from_cvss_score(cls, score: float) -> Severity:
        """Map a CVSS base score to its qualitative rating.

        Thresholds are the ones defined by CVSS v3.1 and kept by v4.0.
        """
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.NONE


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.UNKNOWN: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class Confidence(StrEnum):
    """How much weight a result or an extracted symbol carries."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}[self]


# ---------------------------------------------------------------------------
# Vulnerable symbols
# ---------------------------------------------------------------------------


class SymbolKind(StrEnum):
    """What kind of definition a vulnerable symbol names."""

    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    #: Changed code sat at module level, so importing the module runs it.
    MODULE = "module"


class SymbolSource(StrEnum):
    """Where a vulnerable symbol came from, in descending trustworthiness."""

    #: Hand-reviewed override committed to this repository.
    CURATED = "curated"
    #: Extracted from the diff of the advisory's fix commit.
    FIX_COMMIT = "fix_commit"
    #: Supplied by the advisory itself in OSV ``ecosystem_specific``.
    OSV_ECOSYSTEM_SPECIFIC = "osv_ecosystem_specific"
    #: Derived by diffing release tags because no fix commit was available.
    TAG_DIFF = "tag_diff"
    #: Named by an operator during triage. Least trustworthy of all, not
    #: because the person is wrong but because nothing checked them: no fix
    #: commit was consulted, so the tool cannot confirm the symbol is the
    #: vulnerable one. Never produced by automated extraction.
    MANUAL = "manual"


class SymbolsStatus(StrEnum):
    """Extraction state of an advisory's vulnerable symbols."""

    PENDING = "pending"
    EXTRACTED = "extracted"
    DERIVED_FROM_TAGS = "derived_from_tags"
    #: Extraction ran and legitimately found nothing (a data-only fix, say).
    NONE = "none"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------


class ReachStatus(StrEnum):
    """Outcome of the reachability search for one finding."""

    #: A path exists using only statically resolved call edges.
    REACHABLE_CONFIRMED = "reachable_confirmed"
    #: Paths exist but every one of them relies on a conservatively resolved
    #: dynamic call or passes through an opaque function.
    REACHABLE_POSSIBLE = "reachable_possible"
    #: Vulnerable symbols are known and no path reaches any of them.
    UNREACHABLE = "unreachable"
    #: No vulnerable symbols are known, so no claim can be made.
    SYMBOLS_UNKNOWN = "symbols_unknown"
    #: The call graph is too incomplete to trust either answer.
    GRAPH_INCOMPLETE = "graph_incomplete"

    @property
    def is_conclusive(self) -> bool:
        """Whether the analysis reached an answer, either way.

        ``reachable_confirmed``, ``reachable_possible`` and ``unreachable``
        are answers. ``symbols_unknown`` and ``graph_incomplete`` are not:
        the first means the advisory never said which functions its fix
        changed, the second that the call graph could not be completed. Both
        are "nobody could look", which this project insists is a different
        statement from "not reachable" -- and the distinction is only useful
        if a policy can express it.

        It exists because ``analysed`` could not do this job despite its
        docstring claiming to. ``analysed`` is true whenever reachability
        *ran*, and it runs for ``symbols_unknown``: it runs, finds nothing to
        search for, and says so. A gate written as ``reachable ||
        !analysed`` therefore passes a finding nobody could clear, which is
        the exact failure this tool exists to prevent.
        """
        return self in {
            ReachStatus.REACHABLE_CONFIRMED,
            ReachStatus.REACHABLE_POSSIBLE,
            ReachStatus.UNREACHABLE,
        }

    @property
    def is_reachable(self) -> bool:
        return self in {ReachStatus.REACHABLE_CONFIRMED, ReachStatus.REACHABLE_POSSIBLE}

    @property
    def may_suppress(self) -> bool:
        """Whether this status is allowed to turn a finding into ``not_affected``.

        Only proven unreachability may. Uncertainty never silences a finding;
        see ``docs/00-blueprint.md`` principle 3.
        """
        return self is ReachStatus.UNREACHABLE


class ReachReason(StrEnum):
    """Why a non-definitive reachability status was reached."""

    #: Every path reaches a class definition by import. The class statement
    #: runs; its methods do not.
    CLASS_BODY_ONLY = "class_body_only"
    #: Every match is a module rather than something callable. Importing runs
    #: the module-level code, which is not the same as triggering the
    #: behaviour the advisory describes.
    MODULE_LEVEL_ONLY = "module_level_only"

    #: Reachability analysis is not implemented for the component's ecosystem.
    ECOSYSTEM_UNSUPPORTED = "ecosystem_unsupported"
    #: The advisory has no fix commit to diff.
    NO_FIX_COMMIT = "no_fix_commit"
    #: A fix commit existed but symbol extraction failed on it.
    PATCHDIFF_FAILED = "patchdiff_failed"
    #: Too much first-party source failed to parse.
    PARSE_ERRORS = "parse_errors"
    #: No entry points could be identified, so no search could start.
    ENTRY_POINTS_UNKNOWN = "entry_points_unknown"
    #: The symbols exist but not in the installed version of the package.
    SYMBOLS_NOT_IN_VERSION = "symbols_not_in_version"
    #: The dependency's own call graph was unavailable, so its internals could
    #: not be traversed. A direct call to a vulnerable symbol is still visible,
    #: but an absence of paths proves nothing and must not be reported as one.
    PACKAGE_NOT_ANALYSED = "package_not_analysed"


class EdgeKind(StrEnum):
    """How a call edge in the graph was resolved."""

    #: Callee resolved exactly.
    STATIC = "static"
    #: Callee guessed conservatively from an attribute name or class hierarchy.
    DYNAMIC = "dynamic"
    #: Edge created because the caller is opaque (uses eval, getattr, dynamic
    #: imports) and must be assumed to reach what it can see.
    OPAQUE = "opaque"
    #: Module-level code executed by an import.
    IMPORT = "import"


class EntryPointSource(StrEnum):
    """How the entry points for a scan were determined, best first."""

    #: Listed explicitly in .vexpath.yml.
    CONFIG = "config"
    #: Declared console scripts or package entry points.
    PACKAGE_METADATA = "package_metadata"
    #: ``if __name__ == "__main__"`` blocks and ``__main__.py``.
    DUNDER_MAIN = "dunder_main"
    #: Framework handlers: routes, tasks, management commands, Lambda handlers.
    FRAMEWORK = "framework"
    #: Last resort: every public function of every first-party module.
    FALLBACK_PUBLIC = "fallback_public"


# ---------------------------------------------------------------------------
# Verdicts and VEX
# ---------------------------------------------------------------------------


class Verdict(StrEnum):
    """Our conclusion for a finding. Mirrors the OpenVEX status vocabulary."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"
    FIXED = "fixed"


class VexJustification(StrEnum):
    """OpenVEX justification labels, required when a status is ``not_affected``.

    Spelling is fixed by the OpenVEX specification and must not be altered.
    """

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class CycloneDxAnalysisState(StrEnum):
    """CycloneDX ``vulnerabilities[].analysis.state`` values."""

    RESOLVED = "resolved"
    EXPLOITABLE = "exploitable"
    IN_TRIAGE = "in_triage"
    FALSE_POSITIVE = "false_positive"
    NOT_AFFECTED = "not_affected"
    RESOLVED_WITH_PEDIGREE = "resolved_with_pedigree"


#: How our verdicts map onto CycloneDX analysis states (ADR-0007).
VERDICT_TO_CYCLONEDX_STATE: dict[Verdict, CycloneDxAnalysisState] = {
    Verdict.AFFECTED: CycloneDxAnalysisState.EXPLOITABLE,
    Verdict.NOT_AFFECTED: CycloneDxAnalysisState.NOT_AFFECTED,
    Verdict.UNDER_INVESTIGATION: CycloneDxAnalysisState.IN_TRIAGE,
    Verdict.FIXED: CycloneDxAnalysisState.RESOLVED,
}


# ---------------------------------------------------------------------------
# SBOM and scans
# ---------------------------------------------------------------------------


class ComponentScope(StrEnum):
    """Why a component is present in the dependency set."""

    RUNTIME = "runtime"
    DEV = "dev"
    OPTIONAL = "optional"


class SbomFormat(StrEnum):
    """SBOM document formats this project reads or writes."""

    CYCLONEDX_1_6_JSON = "cyclonedx-1.6-json"
    CYCLONEDX_1_6_XML = "cyclonedx-1.6-xml"
    CYCLONEDX_1_5_JSON = "cyclonedx-1.5-json"
    CYCLONEDX_1_4_JSON = "cyclonedx-1.4-json"
    SPDX_2_3_JSON = "spdx-2.3-json"
    SPDX_2_3_TAGVALUE = "spdx-2.3-tagvalue"
    SPDX_3_0_JSONLD = "spdx-3.0-jsonld"


class SbomGenerator(StrEnum):
    """What produced an SBOM."""

    VEXPATH = "vexpath"
    SYFT = "syft"
    UPLOADED = "uploaded"


class ScanMode(StrEnum):
    """Where a scan ran."""

    CLI = "cli"
    ACTION = "action"
    HOSTED = "hosted"


class ScanStatus(StrEnum):
    """Lifecycle of a scan record."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Visibility(StrEnum):
    """Whether a project's reports are published."""

    PRIVATE = "private"
    PUBLIC = "public"


__all__ = [
    "NATIVE_LOCKFILE_ECOSYSTEMS",
    "REACHABILITY_ECOSYSTEMS",
    "VERDICT_TO_CYCLONEDX_STATE",
    "ComponentScope",
    "Confidence",
    "CycloneDxAnalysisState",
    "EdgeKind",
    "EntryPointSource",
    "ReachReason",
    "ReachStatus",
    "SbomFormat",
    "SbomGenerator",
    "ScanMode",
    "ScanStatus",
    "Severity",
    "SymbolKind",
    "SymbolSource",
    "SymbolsStatus",
    "Verdict",
    "VexJustification",
    "Visibility",
    "canonical_ecosystem",
    "ecosystem_to_purl_type",
    "purl_type_to_ecosystem",
    "supports_reachability",
]
