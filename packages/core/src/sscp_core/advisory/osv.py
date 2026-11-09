"""Normalise OSV records into this project's advisory model.

OSV is the primary advisory source because it aggregates GitHub Security
Advisories, PyPA, Go, RustSec and others behind one schema, and publishes bulk
exports that make an offline, reproducible corpus possible.

Three normalisation decisions are worth stating, because each one changes which
findings a user sees:

*One advisory, one identifier.* The same vulnerability arrives as a CVE, a GHSA
and sometimes an ecosystem identifier. They collapse into a single record whose
primary identifier prefers the CVE, because that is what users search for and
what regulators cite. Every other identifier is kept as an alias so a lookup by
any of them still works.

*Severity comes from the vector.* Where a CVSS vector is present the score is
computed from it rather than read from a numeric field, which upstream data
does not always keep consistent with the vector. The qualitative label from the
source is used only when no scorable vector exists.

*Package names are normalised on the way in.* Advisory matching joins on the
package URL, so a name that is not normalised at ingest silently fails to match
later. That failure mode is invisible, which is why it happens here rather than
being left to the matcher.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sscp_core.cvss import try_base_score, vector_version
from sscp_core.enums import (
    Confidence,
    Severity,
    SymbolKind,
    SymbolSource,
    SymbolsStatus,
    canonical_ecosystem,
)
from sscp_core.models.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    RangeEvent,
    RangeType,
    VulnerableSymbol,
)
from sscp_core.models.common import CvssScore, Reference
from sscp_core.purl import build_purl, normalise_name

#: Qualitative severity labels used by advisory databases, mapped to ours.
#: GitHub says MODERATE where CVSS says MEDIUM.
_SEVERITY_LABELS: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.NONE,
    "INFORMATIONAL": Severity.NONE,
}

#: Reference types that may carry the upstream repository, best first. The
#: repository is where symbol extraction starts, so finding it matters.
_REPO_REFERENCE_TYPES = ("PACKAGE", "FIX", "ADVISORY", "WEB", "SOURCE_CODE")

_REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht")


class OsvRecordError(Exception):
    """Raised when an OSV record cannot be normalised."""


def normalise(record: dict[str, Any]) -> Advisory:
    """Convert one OSV record into an `Advisory`.

    Raises:
        OsvRecordError: if the record has no identifier, which makes it
            unusable, or its affected list is malformed.
    """
    raw_id = record.get("id")
    if not raw_id:
        msg = "OSV record has no id"
        raise OsvRecordError(msg)

    all_ids = [str(raw_id), *(str(alias) for alias in record.get("aliases", []) or [])]
    primary = _primary_identifier(all_ids)
    aliases = tuple(identifier for identifier in dict.fromkeys(all_ids) if identifier != primary)

    cvss_v3, cvss_v4 = _cvss_scores(record)
    severity = _severity(record, cvss_v3, cvss_v4)
    affected = _affected_packages(record)
    symbols = _symbols_from_ecosystem_specific(record, primary)

    return Advisory(
        id=primary,
        aliases=aliases,
        summary=str(record.get("summary") or ""),
        details=str(record.get("details") or ""),
        severity=severity,
        cvss_v3=cvss_v3,
        cvss_v4=cvss_v4,
        cwe_ids=_cwe_ids(record),
        references=_references(record),
        repo_url=_repo_url(record),
        published_at=_timestamp(record.get("published")),
        modified_at=_timestamp(record.get("modified")),
        withdrawn_at=_timestamp(record.get("withdrawn")),
        affected=affected,
        symbols=symbols,
        # Symbols that arrive with the record are already extracted; everything
        # else waits for the patch-diff worker.
        symbols_status=SymbolsStatus.EXTRACTED if symbols else SymbolsStatus.PENDING,
    )


def normalise_all(records: list[dict[str, Any]]) -> tuple[list[Advisory], list[str]]:
    """Normalise many records, collecting failures rather than aborting.

    A bulk export of tens of thousands of records should not be abandoned
    because one of them is malformed. Returns the advisories and a list of
    messages describing what was skipped.
    """
    advisories: list[Advisory] = []
    problems: list[str] = []
    for record in records:
        try:
            advisories.append(normalise(record))
        except (OsvRecordError, ValueError) as exc:
            problems.append(f"{record.get('id', '<no id>')}: {exc}")
    return advisories, problems


def _primary_identifier(identifiers: list[str]) -> str:
    """Pick the identifier users will search for.

    CVE first because it is the cross-ecosystem name and the one cited in
    regulation, then GHSA, then whatever the record called itself.
    """
    for prefix in ("CVE-", "GHSA-"):
        for identifier in identifiers:
            if identifier.upper().startswith(prefix):
                return identifier
    return identifiers[0]


def _cvss_scores(record: dict[str, Any]) -> tuple[CvssScore | None, CvssScore | None]:
    """Extract CVSS version 3 and 4 entries, scoring 3.x from its vector."""
    cvss_v3: CvssScore | None = None
    cvss_v4: CvssScore | None = None

    for entry in record.get("severity", []) or []:
        if not isinstance(entry, dict):
            continue
        # OSV puts the vector string in 'score'; it is not a number.
        vector = str(entry.get("score") or "")
        kind = str(entry.get("type") or "").upper()
        if not vector:
            continue
        version = vector_version(vector)
        if kind == "CVSS_V3" or (version or "").startswith("3."):
            computed = try_base_score(vector)
            if computed is not None and cvss_v3 is None:
                cvss_v3 = CvssScore(
                    version=version if version in {"3.0", "3.1"} else "3.1",
                    vector=vector,
                    base_score=computed,
                )
        elif (kind == "CVSS_V4" or (version or "").startswith("4.")) and cvss_v4 is None:
            # Version 4 base scores come from a large lookup table rather than a
            # formula, so the vector is carried without a computed score and the
            # label falls back to the source's own.
            cvss_v4 = CvssScore(version="4.0", vector=vector, base_score=0.0)
    return cvss_v3, cvss_v4


def _severity(
    record: dict[str, Any], cvss_v3: CvssScore | None, cvss_v4: CvssScore | None
) -> Severity:
    if cvss_v3 is not None:
        return Severity.from_cvss_score(cvss_v3.base_score)

    database_specific = record.get("database_specific", {})
    if isinstance(database_specific, dict):
        label = str(database_specific.get("severity") or "").upper()
        if label in _SEVERITY_LABELS:
            return _SEVERITY_LABELS[label]

    # A version 4 vector with no label leaves severity genuinely unknown, which
    # is reported as such rather than guessed from the vector's shape.
    if cvss_v4 is not None:
        return Severity.UNKNOWN
    return Severity.UNKNOWN


def _cwe_ids(record: dict[str, Any]) -> tuple[str, ...]:
    database_specific = record.get("database_specific", {})
    if not isinstance(database_specific, dict):
        return ()
    raw = database_specific.get("cwe_ids", [])
    if not isinstance(raw, list):
        return ()
    return tuple(dict.fromkeys(str(entry) for entry in raw if entry))


def _references(record: dict[str, Any]) -> tuple[Reference, ...]:
    references: list[Reference] = []
    for entry in record.get("references", []) or []:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not url:
            continue
        references.append(Reference(type=str(entry.get("type") or "WEB"), url=str(url)))
    return tuple(references)


def _repo_url(record: dict[str, Any]) -> str | None:
    """Find the upstream repository, which is where symbol extraction begins.

    A GIT range states the repository outright and is therefore preferred.
    Otherwise a reference URL on a known forge is reduced to its project root.
    """
    for affected in record.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        for entry in affected.get("ranges", []) or []:
            if isinstance(entry, dict) and str(entry.get("type")).upper() == "GIT":
                repo = entry.get("repo")
                if repo:
                    return str(repo)

    references = record.get("references", []) or []
    for wanted in _REPO_REFERENCE_TYPES:
        for entry in references:
            if not isinstance(entry, dict) or str(entry.get("type")).upper() != wanted:
                continue
            root = _repository_root(str(entry.get("url") or ""))
            if root:
                return root
    return None


def _repository_root(url: str) -> str | None:
    """Reduce a forge URL to its repository root, or return None."""
    if not any(host in url for host in _REPO_HOSTS):
        return None
    without_scheme = url.split("://", 1)[-1]
    parts = [part for part in without_scheme.split("/") if part]
    if len(parts) < 3:
        return None
    host, owner, repository = parts[0], parts[1], parts[2]
    if owner in {"advisories", "security"}:
        # github.com/advisories/GHSA-... is the advisory page, not a project.
        return None
    return f"https://{host}/{owner}/{repository.removesuffix('.git')}"


def _affected_packages(record: dict[str, Any]) -> tuple[AffectedPackage, ...]:
    raw_affected = record.get("affected", []) or []
    if not isinstance(raw_affected, list):
        msg = "'affected' must be an array"
        raise OsvRecordError(msg)

    packages: list[AffectedPackage] = []
    for entry in raw_affected:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package", {})
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        ecosystem_raw = package.get("ecosystem")
        if not name or not ecosystem_raw:
            continue

        # OSV qualifies some ecosystems with a distribution, as in
        # "Debian:11" or "Alpine:v3.18". The base name is what matters here.
        ecosystem = canonical_ecosystem(str(ecosystem_raw).split(":", 1)[0])
        normalised_name = normalise_name(ecosystem, str(name))

        packages.append(
            AffectedPackage(
                ecosystem=ecosystem,
                name=normalised_name,
                purl_base=build_purl(ecosystem, normalised_name),
                ranges=_ranges(entry),
                versions=tuple(
                    dict.fromkeys(str(version) for version in entry.get("versions", []) or [])
                ),
            )
        )
    return tuple(packages)


def _ranges(affected: dict[str, Any]) -> tuple[AffectedRange, ...]:
    ranges: list[AffectedRange] = []
    for entry in affected.get("ranges", []) or []:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("type") or "").upper()
        if kind not in {item.value for item in RangeType}:
            continue
        events: list[RangeEvent] = []
        for raw_event in entry.get("events", []) or []:
            if not isinstance(raw_event, dict):
                continue
            event = _event(raw_event)
            if event is not None:
                events.append(event)
        if events:
            ranges.append(
                AffectedRange(
                    type=RangeType(kind),
                    repo=str(entry["repo"]) if entry.get("repo") else None,
                    events=tuple(events),
                )
            )
    return tuple(ranges)


def _event(raw: dict[str, Any]) -> RangeEvent | None:
    """Build one range event, keeping only the field OSV actually set."""
    for field in ("introduced", "fixed", "last_affected", "limit"):
        if field in raw and raw[field] is not None:
            return RangeEvent(**{field: str(raw[field])})
    return None


def _symbols_from_ecosystem_specific(
    record: dict[str, Any], advisory_id: str
) -> tuple[VulnerableSymbol, ...]:
    """Read vulnerable symbols that the record already carries.

    Go advisories publish the affected symbols directly, under
    ``ecosystem_specific.imports``. Where a source has done the work, using it
    is better than rediscovering it by diffing a commit, and the symbols are
    marked as having come from the advisory so their provenance is visible.
    """
    symbols: list[VulnerableSymbol] = []
    for affected in record.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package", {})
        if not isinstance(package, dict) or not package.get("name"):
            continue
        ecosystem = canonical_ecosystem(str(package.get("ecosystem", "")).split(":", 1)[0])
        package_name = normalise_name(ecosystem, str(package["name"]))

        ecosystem_specific = affected.get("ecosystem_specific", {})
        if not isinstance(ecosystem_specific, dict):
            continue
        for entry in ecosystem_specific.get("imports", []) or []:
            if not isinstance(entry, dict):
                continue
            module = str(entry.get("path") or "")
            for symbol in entry.get("symbols", []) or []:
                qualified = f"{module}.{symbol}" if module else str(symbol)
                symbols.append(
                    VulnerableSymbol(
                        advisory_id=advisory_id,
                        ecosystem=ecosystem,
                        package_name=package_name,
                        symbol=qualified,
                        kind=SymbolKind.FUNCTION,
                        source=SymbolSource.OSV_ECOSYSTEM_SPECIFIC,
                        # The source states these outright, so they are as
                        # trustworthy as a reviewed extraction.
                        confidence=Confidence.HIGH,
                        file_path=module or None,
                    )
                )
    return tuple(symbols)


def _timestamp(value: Any) -> datetime | None:
    """Parse an RFC 3339 timestamp, tolerating the forms OSV actually emits."""
    if not value:
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # OSV requires an offset, but a naive timestamp from a mirror is
        # better read as UTC than discarded.
        from datetime import UTC

        return parsed.replace(tzinfo=UTC)
    return parsed


__all__ = ["OsvRecordError", "normalise", "normalise_all"]
