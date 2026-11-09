"""Normalising OSV records.

Normalisation decides which findings a user ever sees. A name that is not
normalised here fails to match later, silently, so these tests check the
boundary rather than trusting it.
"""

from __future__ import annotations

from typing import Any

import pytest

from sscp_core.advisory.osv import OsvRecordError, normalise, normalise_all
from sscp_core.enums import Severity, SymbolSource, SymbolsStatus


def _record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "GHSA-9wx4-h78v-vm56",
        "aliases": ["CVE-2024-35195"],
        "summary": "Session verification bypass",
        "details": "Longer description.",
        "modified": "2024-05-21T00:00:00Z",
        "published": "2024-05-20T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Requests"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.32.0"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-9wx4-h78v-vm56"},
            {"type": "PACKAGE", "url": "https://github.com/psf/requests"},
        ],
        "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-295"]},
    }
    return base | overrides


def test_the_cve_becomes_the_primary_identifier() -> None:
    """Users search for CVEs and regulators cite them, so a CVE wins."""
    advisory = normalise(_record())
    assert advisory.id == "CVE-2024-35195"
    assert "GHSA-9wx4-h78v-vm56" in advisory.aliases
    # A lookup by any known name still resolves.
    assert set(advisory.all_ids) == {"CVE-2024-35195", "GHSA-9wx4-h78v-vm56"}


def test_a_ghsa_wins_when_there_is_no_cve() -> None:
    advisory = normalise(_record(aliases=[]))
    assert advisory.id == "GHSA-9wx4-h78v-vm56"
    assert advisory.aliases == ()


def test_an_ecosystem_identifier_is_kept_when_it_is_all_there_is() -> None:
    advisory = normalise(_record(id="PYSEC-2024-0001", aliases=[]))
    assert advisory.id == "PYSEC-2024-0001"


def test_package_names_are_normalised_at_ingest() -> None:
    # Matching joins on the purl, so an unnormalised name here fails to match
    # later with no error anywhere.
    advisory = normalise(_record())
    package = advisory.affected[0]
    assert package.name == "requests"
    assert package.purl_base == "pkg:pypi/requests"


def test_severity_is_computed_from_the_vector_not_the_label() -> None:
    """Upstream labels and vectors disagree; the vector is authoritative."""
    advisory = normalise(_record())
    assert advisory.cvss_v3 is not None
    assert advisory.cvss_v3.base_score == pytest.approx(5.3)
    assert advisory.severity is Severity.MEDIUM


def test_the_qualitative_label_is_used_only_without_a_scorable_vector() -> None:
    advisory = normalise(_record(severity=[]))
    assert advisory.cvss_v3 is None
    # MODERATE is GitHub's spelling of MEDIUM.
    assert advisory.severity is Severity.MEDIUM


def test_severity_is_unknown_when_nothing_says_otherwise() -> None:
    advisory = normalise(_record(severity=[], database_specific={}))
    assert advisory.severity is Severity.UNKNOWN


def test_a_version_4_vector_is_carried_without_a_fabricated_score() -> None:
    advisory = normalise(
        _record(
            severity=[
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                }
            ],
            database_specific={"severity": "CRITICAL"},
        )
    )
    assert advisory.cvss_v4 is not None
    assert advisory.cvss_v4.base_score == 0.0
    # The label comes from the source, because 4.0 cannot be scored here.
    assert advisory.severity is Severity.CRITICAL


def test_the_repository_is_found_for_symbol_extraction() -> None:
    # Symbol extraction starts from the repository, so finding it matters more
    # than it looks.
    advisory = normalise(_record())
    assert advisory.repo_url == "https://github.com/psf/requests"


def test_a_git_range_names_the_repository_outright() -> None:
    advisory = normalise(
        _record(
            affected=[
                {
                    "package": {"ecosystem": "PyPI", "name": "requests"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/psf/requests",
                            "events": [{"introduced": "0"}],
                        }
                    ],
                }
            ],
            references=[],
        )
    )
    assert advisory.repo_url == "https://github.com/psf/requests"


def test_an_advisory_page_is_not_mistaken_for_a_repository() -> None:
    advisory = normalise(
        _record(references=[{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-xxxx"}])
    )
    assert advisory.repo_url is None


def test_distribution_qualified_ecosystems_reduce_to_their_base() -> None:
    # OSV writes "Debian:11" and "Alpine:v3.18"; the base name is what matches.
    advisory = normalise(
        _record(
            affected=[
                {
                    "package": {"ecosystem": "Debian:11", "name": "curl"},
                    "versions": ["7.74.0-1"],
                }
            ]
        )
    )
    assert advisory.affected[0].ecosystem == "Debian"


def test_range_events_keep_their_osv_shape() -> None:
    advisory = normalise(_record())
    events = advisory.affected[0].ranges[0].events
    assert events[0].introduced == "0"
    assert events[1].fixed == "2.32.0"
    assert advisory.affected[0].fixed_versions == ("2.32.0",)


def test_symbols_are_read_where_the_source_provides_them() -> None:
    """Go advisories name affected symbols, and using them beats rediscovery."""
    advisory = normalise(
        _record(
            id="GO-2024-0001",
            aliases=[],
            affected=[
                {
                    "package": {"ecosystem": "Go", "name": "github.com/example/pkg"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                    ],
                    "ecosystem_specific": {
                        "imports": [
                            {"path": "github.com/example/pkg/sub", "symbols": ["Parse", "Decode"]}
                        ]
                    },
                }
            ],
        )
    )
    assert advisory.symbols_status is SymbolsStatus.EXTRACTED
    assert {symbol.symbol for symbol in advisory.symbols} == {
        "github.com/example/pkg/sub.Parse",
        "github.com/example/pkg/sub.Decode",
    }
    assert all(symbol.source is SymbolSource.OSV_ECOSYSTEM_SPECIFIC for symbol in advisory.symbols)


def test_symbols_are_pending_when_the_record_carries_none() -> None:
    advisory = normalise(_record())
    assert advisory.symbols == ()
    assert advisory.symbols_status is SymbolsStatus.PENDING


def test_withdrawal_is_preserved() -> None:
    advisory = normalise(_record(withdrawn="2024-06-03T00:00:00Z"))
    assert advisory.is_withdrawn


def test_a_record_without_an_identifier_is_rejected() -> None:
    with pytest.raises(OsvRecordError, match="no id"):
        normalise({"summary": "nameless"})


def test_bulk_normalisation_skips_bad_records_rather_than_aborting() -> None:
    # A corpus of tens of thousands must not be abandoned over one bad record.
    advisories, problems = normalise_all([_record(), {"summary": "nameless"}, _record(id="X")])
    assert len(advisories) == 2
    assert len(problems) == 1
    assert "no id" in problems[0]


def test_timestamps_become_aware_datetimes() -> None:
    advisory = normalise(_record())
    assert advisory.published_at is not None
    assert advisory.published_at.tzinfo is not None
    assert advisory.modified_at is not None
