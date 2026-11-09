"""EPSS and CISA KEV enrichment.

These signals change what to fix first, never what is reported, and that
asymmetry is what most of these tests assert. The rest cover the two feed
formats and the one lookup subtlety that would silently lose most of a corpus.
"""

from __future__ import annotations

import gzip
import json
from datetime import date

import httpx
import pytest

from vexpath_core.advisory.enrich import (
    EnrichmentError,
    ExploitSignals,
    enrich,
    enrich_all,
    fetch_signals,
    highest_priority,
    parse_epss,
    parse_kev,
    signals_from_mapping,
)
from vexpath_core.enums import Severity, Verdict
from vexpath_core.models.advisory import Advisory

EPSS_CSV = """\
#model_version:v2025.03.14,score_date:2026-11-09T00:00:00+0000
cve,epss,percentile
CVE-2024-35195,0.00042,0.11000
CVE-2023-45803,0.91000,0.99900
CVE-2020-14343,0.00500,0.60000
"""

KEV_JSON = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "vulnerabilities": [
        {"cveID": "CVE-2023-45803", "dateAdded": "2026-03-01", "vendorProject": "urllib3"},
        {"cveID": "CVE-2020-14343", "dateAdded": "not a date"},
    ],
}


def _advisory(identifier: str = "CVE-2024-35195", **overrides: object) -> Advisory:
    return Advisory.model_validate({"id": identifier, "severity": Severity.HIGH, **overrides})


def _signals() -> ExploitSignals:
    return ExploitSignals(
        epss=parse_epss(EPSS_CSV.encode("utf-8")),
        kev=parse_kev(json.dumps(KEV_JSON).encode("utf-8")),
    )


# --- The feed formats -----------------------------------------------------


def test_the_epss_export_parses_past_its_comment_line() -> None:
    scores = parse_epss(EPSS_CSV.encode("utf-8"))
    assert scores["CVE-2023-45803"].score == pytest.approx(0.91)
    assert scores["CVE-2023-45803"].percentile == pytest.approx(0.999)
    assert len(scores) == 3


def test_a_gzipped_export_parses_too() -> None:
    # The published file is gzipped; a cached copy often is not.
    scores = parse_epss(gzip.compress(EPSS_CSV.encode("utf-8")))
    assert "CVE-2024-35195" in scores


def test_an_unparseable_row_is_skipped_rather_than_failing_the_file() -> None:
    """A signal missing for one CVE is smaller than no signal for any."""
    broken = EPSS_CSV + "CVE-2026-0001,not-a-number,0.5\nCVE-2026-0002,0.25,0.75\n"
    scores = parse_epss(broken.encode("utf-8"))
    assert "CVE-2026-0001" not in scores
    assert scores["CVE-2026-0002"].score == pytest.approx(0.25)


def test_an_export_that_parses_to_nothing_is_an_error() -> None:
    """Silence would look like "no CVE is likely to be exploited"."""
    with pytest.raises(EnrichmentError, match="format has probably changed"):
        parse_epss(b"cve,epss,percentile\n")


def test_the_kev_catalogue_parses_to_dates() -> None:
    entries = parse_kev(json.dumps(KEV_JSON).encode("utf-8"))
    assert entries["CVE-2023-45803"] == date(2026, 3, 1)
    assert len(entries) == 2


def test_an_unreadable_kev_date_does_not_drop_the_entry() -> None:
    """The date is presentational; "actively exploited" is not."""
    entries = parse_kev(json.dumps(KEV_JSON).encode("utf-8"))
    assert "CVE-2020-14343" in entries


def test_a_catalogue_in_the_wrong_shape_is_an_error() -> None:
    with pytest.raises(EnrichmentError, match="vulnerabilities"):
        parse_kev(b'{"title": "x"}')

    with pytest.raises(EnrichmentError, match="not readable JSON"):
        parse_kev(b"<html>404</html>")


# --- Attaching the signals ------------------------------------------------


def test_scores_attach_to_an_advisory() -> None:
    enriched = enrich(_advisory("CVE-2023-45803"), _signals())
    assert enriched.epss_score == pytest.approx(0.91)
    assert enriched.epss_percentile == pytest.approx(0.999)
    assert enriched.kev is True
    assert enriched.kev_added_at == date(2026, 3, 1)


def test_an_advisory_is_matched_by_its_aliases() -> None:
    """Both feeds are keyed by CVE, and much of OSV is GHSA-primary.

    Looking up only the primary identifier would miss most of the corpus
    silently, which is the kind of gap that shows up as "the scores look low".
    """
    enriched = enrich(_advisory("GHSA-g4mx-q9vg-27p4", aliases=("CVE-2023-45803",)), _signals())
    assert enriched.epss_score == pytest.approx(0.91)
    assert enriched.kev is True


def test_an_unknown_advisory_is_left_alone() -> None:
    """An unscored advisory must stay distinguishable from one scored zero.

    A real EPSS score of 0.0 says exploitation is very unlikely, which is
    useful. Inventing it would be a claim nobody made.
    """
    enriched = enrich(_advisory("CVE-2026-99999"), _signals())
    assert enriched.epss_score is None
    assert enriched.kev is False
    assert enriched.kev_added_at is None


def test_enrichment_never_changes_whether_something_is_reported() -> None:
    """These signals are for ordering, not for deciding."""
    before = _advisory("CVE-2024-35195", severity=Severity.HIGH)
    after = enrich(before, _signals())

    assert after.severity is before.severity
    assert after.affected == before.affected
    assert after.symbols == before.symbols
    assert after.withdrawn_at == before.withdrawn_at
    assert after.is_withdrawn == before.is_withdrawn
    # A very low EPSS score does not suppress anything.
    assert after.epss_score == pytest.approx(0.00042)


def test_a_whole_corpus_reports_how_much_landed() -> None:
    corpus = [
        _advisory("CVE-2024-35195"),
        _advisory("CVE-2023-45803"),
        _advisory("CVE-2026-99999"),
    ]
    enriched, counts = enrich_all(corpus, _signals())

    assert counts.advisories == 3
    assert counts.with_epss == 2
    assert counts.with_kev == 1
    assert counts.epss_coverage == pytest.approx(2 / 3)
    assert "known exploited" in counts.summary_line()
    assert len(enriched) == 3


# --- Prioritisation -------------------------------------------------------


def test_known_exploited_outranks_a_higher_severity_prediction() -> None:
    """KEV is not a prediction, so it comes before everything that is."""
    exploited_medium = enrich(_advisory("CVE-2023-45803", severity=Severity.MEDIUM), _signals())
    unexploited_critical = enrich(
        _advisory("CVE-2024-35195", severity=Severity.CRITICAL), _signals()
    )

    order = highest_priority([unexploited_critical, exploited_medium])
    assert order[0].id == "CVE-2023-45803"


def test_epss_breaks_ties_between_severities() -> None:
    higher = enrich(_advisory("CVE-2020-14343", severity=Severity.LOW), _signals())
    lower = enrich(_advisory("CVE-2024-35195", severity=Severity.LOW), _signals())
    order = highest_priority([lower, higher])
    assert [advisory.id for advisory in order] == ["CVE-2020-14343", "CVE-2024-35195"]


def test_the_order_is_stable_for_identical_signals() -> None:
    first = _advisory("CVE-2026-0002", severity=Severity.HIGH)
    second = _advisory("CVE-2026-0001", severity=Severity.HIGH)
    order = highest_priority([first, second])
    assert [advisory.id for advisory in order] == ["CVE-2026-0001", "CVE-2026-0002"]


# --- Fetching -------------------------------------------------------------


def test_both_feeds_are_downloaded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "epss" in str(request.url):
            return httpx.Response(200, content=gzip.compress(EPSS_CSV.encode("utf-8")))
        return httpx.Response(200, json=KEV_JSON)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        signals = fetch_signals(client=client)

    assert len(signals.epss) == 3
    assert len(signals.kev) == 2
    assert signals.failures == ()
    assert not signals.is_empty


def test_one_feed_being_down_does_not_lose_the_other() -> None:
    """A third party's outage must not stop a security tool from updating."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "epss" in str(request.url):
            return httpx.Response(503, text="unavailable")
        return httpx.Response(200, json=KEV_JSON)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        signals = fetch_signals(client=client)

    assert signals.epss == {}
    assert len(signals.kev) == 2
    assert len(signals.failures) == 1
    assert "EPSS" in signals.failures[0]
    assert "unavailable" in signals.summary_line()


def test_both_feeds_down_is_still_not_an_exception() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        signals = fetch_signals(client=client)

    assert signals.is_empty
    assert len(signals.failures) == 2


def test_signals_can_be_built_from_plain_data() -> None:
    signals = signals_from_mapping(
        {"cve-2024-35195": (0.5, 0.9)}, {"cve-2023-45803": date(2026, 1, 1)}
    )
    # Identifiers are upper-cased on the way in, so a lower-case cache or a
    # hand-written fixture matches.
    enriched = enrich(_advisory("CVE-2024-35195"), signals)
    assert enriched.epss_score == pytest.approx(0.5)
    assert enrich(_advisory("CVE-2023-45803"), signals).kev is True


# --- Inside a sync --------------------------------------------------------


def test_a_sync_enriches_the_corpus_it_writes(tmp_path: object) -> None:
    from pathlib import Path

    from vexpath_core.advisory.sync import sync
    from vexpath_core.snapshot import read_snapshot

    assert isinstance(tmp_path, Path)
    archive = _zip_of(
        [
            {"id": "CVE-2023-45803", "affected": _affected("urllib3")},
            {"id": "CVE-2024-35195", "affected": _affected("requests")},
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=archive)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = sync(
            tmp_path / "out",
            ecosystems=["PyPI"],
            client=client,
            signals=_signals(),
        )

    assert report.enrichment is not None
    assert report.enrichment.with_epss == 2
    assert report.enrichment.with_kev == 1
    assert "known exploited" in report.summary_line()

    _, records = read_snapshot(tmp_path / "out")
    scored = next(record for record in records if record.id == "CVE-2023-45803")
    assert scored.kev is True
    assert scored.epss_score == pytest.approx(0.91)


def test_a_sync_without_enrichment_writes_an_unscored_corpus(tmp_path: object) -> None:
    from pathlib import Path

    from vexpath_core.advisory.sync import sync

    assert isinstance(tmp_path, Path)
    archive = _zip_of([{"id": "CVE-2023-45803", "affected": _affected("urllib3")}])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=archive)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = sync(tmp_path / "out", ecosystems=["PyPI"], client=client, enrich=False)

    assert report.enrichment is None
    assert report.enrichment_failures == ()


def _affected(name: str) -> list[dict[str, object]]:
    return [
        {
            "package": {"ecosystem": "PyPI", "name": name},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "99.0"}]}],
        }
    ]


def _zip_of(records: list[dict[str, object]]) -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for record in records:
            archive.writestr(f"{record['id']}.json", json.dumps(record))
    return buffer.getvalue()


def test_a_finding_carries_the_signals_through_to_a_report() -> None:
    """The point of the exercise: a reader sees them on the finding."""
    from vexpath_core.enums import ComponentScope
    from vexpath_core.models.finding import AdvisoryRef, ComponentRef, Finding

    enriched = enrich(_advisory("CVE-2023-45803"), _signals())
    finding = Finding(
        id="01",
        advisory=AdvisoryRef(
            id=enriched.id,
            severity=enriched.severity,
            epss_score=enriched.epss_score,
            kev=enriched.kev,
        ),
        component=ComponentRef(
            purl="pkg:pypi/urllib3@1.26.17",
            ecosystem="PyPI",
            name="urllib3",
            version="1.26.17",
            direct=True,
            scope=ComponentScope.RUNTIME,
        ),
        verdict=Verdict.AFFECTED,
    )
    assert finding.advisory.kev is True
    assert finding.advisory.epss_score == pytest.approx(0.91)
