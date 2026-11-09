"""Generate the frozen advisory snapshot used by tests and local development.

Run with ``make regen-snapshot``. The snapshot's integrity hash is computed from
the advisories, so the only correct way to change the fixture is to edit this
script and regenerate.

The advisories here are *fixtures*. Their identifiers, affected ranges and fixed
versions are real, because tests that match versions should match real ones.
Their vulnerable symbols are hand-authored: ``source`` is ``curated`` on every
one, and no fix commits are claimed. Extracting real symbols from real fix
commits is the job of the patch-diff worker in M2, and pretending to have done
it here would put unverified claims into a file that looks authoritative.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

from sscp_core.enums import (
    Confidence,
    Severity,
    SymbolKind,
    SymbolSource,
    SymbolsStatus,
)
from sscp_core.models.advisory import (
    Advisory,
    AdvisorySnapshot,
    AffectedPackage,
    AffectedRange,
    RangeEvent,
    RangeType,
    VulnerableSymbol,
)
from sscp_core.models.common import CvssScore, Reference
from sscp_core.purl import build_purl
from sscp_core.snapshot import write_snapshot

SNAPSHOT_ID = "test-snapshot-0001"
OUTPUT_DIR = Path(__file__).resolve().parents[1] / "testdata" / "advisories"


def _utc(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, tzinfo=UTC)


def _pypi_range(introduced: str, fixed: str | None) -> AffectedRange:
    events = [RangeEvent(introduced=introduced)]
    if fixed is not None:
        events.append(RangeEvent(fixed=fixed))
    return AffectedRange(type=RangeType.ECOSYSTEM, events=tuple(events))


def _affected(ecosystem: str, name: str, introduced: str, fixed: str | None) -> AffectedPackage:
    return AffectedPackage(
        ecosystem=ecosystem,
        name=name,
        purl_base=build_purl(ecosystem, name),
        ranges=(_pypi_range(introduced, fixed),),
    )


def _symbol(
    advisory_id: str,
    package: str,
    symbol: str,
    kind: SymbolKind = SymbolKind.METHOD,
    ecosystem: str = "PyPI",
) -> VulnerableSymbol:
    return VulnerableSymbol(
        advisory_id=advisory_id,
        ecosystem=ecosystem,
        package_name=package,
        symbol=symbol,
        kind=kind,
        # Hand-authored for the fixture, not extracted from a real fix commit.
        source=SymbolSource.CURATED,
        confidence=Confidence.HIGH,
    )


def build_advisories() -> list[Advisory]:
    """Return the fixture advisory corpus.

    Each entry exists to exercise one path through the pipeline; the comment on
    each says which.
    """
    return [
        # Reachable through a direct call and through a method chain. The
        # workhorse fixture for the happy path.
        Advisory(
            id="CVE-2024-35195",
            aliases=("GHSA-9wx4-h78v-vm56",),
            summary="Requests session retains certificate verification bypass across requests",
            details=(
                "When making requests to the same host with `verify=False`, subsequent "
                "requests to that host continue to skip certificate verification even "
                "when `verify=True` is passed."
            ),
            severity=Severity.MEDIUM,
            cvss_v3=CvssScore(
                version="3.1",
                vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                base_score=5.6,
            ),
            cwe_ids=("CWE-295",),
            references=(
                Reference(type="ADVISORY", url="https://github.com/advisories/GHSA-9wx4-h78v-vm56"),
                Reference(type="PACKAGE", url="https://github.com/psf/requests"),
            ),
            repo_url="https://github.com/psf/requests",
            published_at=_utc(2024, 5, 20),
            modified_at=_utc(2024, 5, 21),
            affected=(_affected("PyPI", "requests", "0", "2.32.0"),),
            symbols=(
                _symbol("CVE-2024-35195", "requests", "requests.sessions.Session.send"),
                _symbol("CVE-2024-35195", "requests", "requests.adapters.HTTPAdapter.send"),
            ),
            symbols_status=SymbolsStatus.EXTRACTED,
        ),
        # Module-level vulnerable code: importing the module is enough, so this
        # fixture checks that an import counts as reaching it.
        Advisory(
            id="CVE-2020-14343",
            aliases=("GHSA-8q59-q68h-6hv4",),
            summary="PyYAML full_load can execute arbitrary code through python/object/apply",
            details=(
                "A vulnerability in the PyYAML library allows arbitrary code execution "
                "when untrusted YAML is processed with the FullLoader loader."
            ),
            severity=Severity.CRITICAL,
            cvss_v3=CvssScore(
                version="3.1",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=9.8,
            ),
            cwe_ids=("CWE-20", "CWE-502"),
            references=(
                Reference(type="ADVISORY", url="https://github.com/advisories/GHSA-8q59-q68h-6hv4"),
            ),
            repo_url="https://github.com/yaml/pyyaml",
            published_at=_utc(2021, 2, 9),
            modified_at=_utc(2021, 3, 1),
            affected=(_affected("PyPI", "pyyaml", "0", "5.4"),),
            symbols=(
                _symbol(
                    "CVE-2020-14343",
                    "pyyaml",
                    "yaml.constructor",
                    kind=SymbolKind.MODULE,
                ),
            ),
            symbols_status=SymbolsStatus.EXTRACTED,
        ),
        # Reachable only through a subclass override, to check class-hierarchy
        # analysis.
        Advisory(
            id="CVE-2024-22195",
            aliases=("GHSA-h5c8-rqwp-cp95",),
            summary="Jinja2 xmlattr filter accepts keys containing spaces and quotes",
            details=(
                "The xmlattr filter does not validate attribute keys, allowing injection "
                "of additional attributes into rendered markup."
            ),
            severity=Severity.MEDIUM,
            cvss_v3=CvssScore(
                version="3.1",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                base_score=6.1,
            ),
            cwe_ids=("CWE-79",),
            references=(
                Reference(type="ADVISORY", url="https://github.com/advisories/GHSA-h5c8-rqwp-cp95"),
            ),
            repo_url="https://github.com/pallets/jinja",
            published_at=_utc(2024, 1, 11),
            modified_at=_utc(2024, 1, 12),
            affected=(_affected("PyPI", "jinja2", "0", "3.1.3"),),
            symbols=(
                _symbol(
                    "CVE-2024-22195",
                    "jinja2",
                    "jinja2.filters.do_xmlattr",
                    kind=SymbolKind.FUNCTION,
                ),
            ),
            symbols_status=SymbolsStatus.EXTRACTED,
        ),
        # Present in the lockfile but never imported: the fixture for a verdict
        # of not_affected with the "never imported" impact statement.
        Advisory(
            id="CVE-2023-45803",
            aliases=("GHSA-g4mx-q9vg-27p4",),
            summary="urllib3 keeps the request body after an HTTP redirect that drops it",
            details=(
                "urllib3 does not remove the request body when a redirect changes the "
                "method to GET or HEAD, which can leak the body to another endpoint."
            ),
            severity=Severity.MEDIUM,
            cwe_ids=("CWE-200",),
            references=(
                Reference(type="ADVISORY", url="https://github.com/advisories/GHSA-g4mx-q9vg-27p4"),
            ),
            repo_url="https://github.com/urllib3/urllib3",
            published_at=_utc(2023, 10, 17),
            modified_at=_utc(2023, 10, 18),
            affected=(_affected("PyPI", "urllib3", "0", "1.26.18"),),
            symbols=(
                _symbol(
                    "CVE-2023-45803",
                    "urllib3",
                    "urllib3.poolmanager.PoolManager.urlopen",
                ),
            ),
            symbols_status=SymbolsStatus.EXTRACTED,
        ),
        # Reached only through a dynamically resolved call, which must produce
        # reachable_possible rather than reachable_confirmed.
        Advisory(
            id="CVE-2024-FIXTURE-DYNAMIC",
            summary="Fixture advisory reachable only through a dynamically dispatched call",
            details=(
                "Not a real vulnerability. Exists so the benchmark can assert that a "
                "path which depends on a conservatively resolved call is reported as "
                "possible rather than confirmed."
            ),
            severity=Severity.HIGH,
            affected=(_affected("PyPI", "fixturelib", "0", "2.0.0"),),
            symbols=(
                _symbol(
                    "CVE-2024-FIXTURE-DYNAMIC",
                    "fixturelib",
                    "fixturelib.handlers.Handler.process",
                ),
            ),
            symbols_status=SymbolsStatus.EXTRACTED,
        ),
        # No symbols could be extracted: must become under_investigation, never
        # a clean result.
        Advisory(
            id="CVE-2024-FIXTURE-NOSYMBOLS",
            summary="Fixture advisory whose fix changed only data, so no symbol exists",
            details=(
                "Not a real vulnerability. Exists so the pipeline can be checked to "
                "report under_investigation when there is nothing to search for."
            ),
            severity=Severity.HIGH,
            affected=(_affected("PyPI", "datafix", "0", "1.4.2"),),
            symbols_status=SymbolsStatus.NONE,
        ),
        # Non-Python ecosystem: reachability is unsupported (ADR-0012), and the
        # result must say so instead of implying the component was checked.
        Advisory(
            id="CVE-2021-23337",
            aliases=("GHSA-35jh-r3h4-6jhm",),
            summary="lodash command injection through template",
            details="lodash versions before 4.17.21 are vulnerable to command injection.",
            severity=Severity.HIGH,
            cwe_ids=("CWE-77",),
            references=(
                Reference(type="ADVISORY", url="https://github.com/advisories/GHSA-35jh-r3h4-6jhm"),
            ),
            repo_url="https://github.com/lodash/lodash",
            published_at=_utc(2021, 2, 15),
            modified_at=_utc(2021, 3, 2),
            affected=(_affected("npm", "lodash", "0", "4.17.21"),),
            symbols_status=SymbolsStatus.PENDING,
        ),
        # Withdrawn: must never produce a finding.
        Advisory(
            id="CVE-2024-FIXTURE-WITHDRAWN",
            summary="Fixture advisory that was withdrawn after publication",
            details=(
                "Not a real vulnerability. Exists so matching can be checked to skip "
                "withdrawn advisories."
            ),
            severity=Severity.CRITICAL,
            affected=(_affected("PyPI", "requests", "0", "99.0.0"),),
            published_at=_utc(2024, 6, 1),
            modified_at=_utc(2024, 6, 3),
            withdrawn_at=_utc(2024, 6, 3),
            symbols_status=SymbolsStatus.NONE,
        ),
    ]


def main() -> int:
    advisories = build_advisories()
    snapshot = AdvisorySnapshot(
        id=SNAPSHOT_ID,
        created_at=_utc(2026, 11, 9),
        # Recomputed by write_snapshot from the advisories themselves.
        content_sha256="0" * 64,
        ecosystems=(),
    )
    stored = write_snapshot(OUTPUT_DIR, snapshot, advisories)
    print(f"wrote {len(advisories)} advisories to {OUTPUT_DIR}")
    print(f"content_sha256 {stored.content_sha256}")
    for ecosystem, counts in sorted(stored.counts.items()):
        print(
            f"  {ecosystem}: {counts['advisories']} advisories, {counts['with_symbols']} with symbols"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
