"""Downloading and normalising an advisory corpus.

The HTTP client is injected, so these tests build real zip archives in memory
and serve them through a stub transport. Nothing touches the network, which is
what lets them run in CI on every commit rather than nightly.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

import httpx
import pytest

from vexpath_core.advisory.sync import (
    MAX_ARCHIVE_BYTES,
    OSV_EXPORT_BASE,
    AdvisorySyncError,
    sync,
)
from vexpath_core.snapshot import read_snapshot


def _record(
    advisory_id: str,
    *,
    name: str,
    ecosystem: str,
    aliases: list[str] | None = None,
    fixed: str = "2.0.0",
) -> dict[str, Any]:
    return {
        "id": advisory_id,
        "aliases": aliases or [],
        "summary": f"{advisory_id} summary",
        "modified": "2026-01-01T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}
                ],
            }
        ],
    }


def _archive(records: list[dict[str, Any]], *, extra_files: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for record in records:
            bundle.writestr(f"{record['id']}.json", json.dumps(record))
        if extra_files:
            # Real exports carry files that are not advisories.
            bundle.writestr("README.txt", "not an advisory")
            bundle.writestr("broken.json", "{ this is not json")
    return buffer.getvalue()


def _transport(archives: dict[str, bytes]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        for ecosystem, payload in archives.items():
            if request.url.path == f"/{ecosystem}/all.zip":
                return httpx.Response(200, content=payload)
        return httpx.Response(404, text="not found")

    return httpx.MockTransport(handler)


def _client(archives: dict[str, bytes]) -> httpx.Client:
    return httpx.Client(transport=_transport(archives), base_url=OSV_EXPORT_BASE)


def test_a_sync_writes_a_verifiable_snapshot(tmp_path: Path) -> None:
    archives = {"PyPI": _archive([_record("CVE-2026-0001", name="Requests", ecosystem="PyPI")])}
    with _client(archives) as client:
        report = sync(tmp_path, ecosystems=["PyPI"], client=client, snapshot_id="s1")

    assert report.advisories == 1
    # Reading it back verifies the integrity hash, so a snapshot that does not
    # match its contents fails here.
    metadata, advisories = read_snapshot(tmp_path)
    assert metadata.id == "s1"
    assert advisories[0].id == "CVE-2026-0001"
    # Names are normalised on the way in, which is what matching joins on.
    assert advisories[0].affected[0].name == "requests"


def test_non_advisory_files_in_the_archive_are_ignored(tmp_path: Path) -> None:
    archives = {
        "PyPI": _archive(
            [_record("CVE-2026-0001", name="requests", ecosystem="PyPI")], extra_files=True
        )
    }
    with _client(archives) as client:
        report = sync(tmp_path, ecosystems=["PyPI"], client=client)
    # The README and the malformed JSON are skipped silently; a real export
    # contains both, and neither is an advisory.
    assert report.advisories == 1


def test_several_ecosystems_are_combined(tmp_path: Path) -> None:
    archives = {
        "PyPI": _archive([_record("CVE-2026-0001", name="requests", ecosystem="PyPI")]),
        "npm": _archive([_record("CVE-2026-0002", name="lodash", ecosystem="npm")]),
    }
    with _client(archives) as client:
        report = sync(tmp_path, ecosystems=["PyPI", "npm"], client=client)

    assert report.advisories == 2
    assert set(report.snapshot.counts) == {"PyPI", "npm"}


def test_aliased_records_from_two_exports_merge(tmp_path: Path) -> None:
    """The same vulnerability in two ecosystems must not be reported twice."""
    archives = {
        "PyPI": _archive(
            [
                _record(
                    "GHSA-aaaa-bbbb-cccc",
                    name="shared",
                    ecosystem="PyPI",
                    aliases=["CVE-2026-9999"],
                )
            ]
        ),
        "npm": _archive(
            [
                _record(
                    "CVE-2026-9999",
                    name="shared-js",
                    ecosystem="npm",
                )
            ]
        ),
    }
    with _client(archives) as client:
        report = sync(tmp_path, ecosystems=["PyPI", "npm"], client=client)

    assert report.advisories == 1
    _, advisories = read_snapshot(tmp_path)
    merged = advisories[0]
    assert merged.id == "CVE-2026-9999"
    # Both affected packages survive the merge, so neither ecosystem loses its
    # finding.
    assert {package.name for package in merged.affected} == {"shared", "shared-js"}


def test_symbol_coverage_is_measured_on_every_sync(tmp_path: Path) -> None:
    """This is the number that decides whether reachability is worth building."""
    with_symbols = {
        "id": "GO-2026-0001",
        "modified": "2026-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "example.com/pkg"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
                "ecosystem_specific": {
                    "imports": [{"path": "example.com/pkg", "symbols": ["Parse"]}]
                },
            }
        ],
    }
    without = _record("GO-2026-0002", name="example.com/other", ecosystem="Go")
    archives = {"Go": _archive([with_symbols, without])}

    with _client(archives) as client:
        report = sync(tmp_path, ecosystems=["Go"], client=client)

    assert report.snapshot.counts["Go"]["advisories"] == 2
    assert report.snapshot.counts["Go"]["with_symbols"] == 1
    assert report.symbol_coverage["Go"] == pytest.approx(0.5)
    assert "symbol coverage 50.0%" in report.summary_line()


def test_malformed_records_are_counted_not_fatal(tmp_path: Path) -> None:
    # A corpus of tens of thousands must not be abandoned over one bad record.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr(
            "good.json", json.dumps(_record("CVE-2026-0001", name="a", ecosystem="PyPI"))
        )
        bundle.writestr("nameless.json", json.dumps({"summary": "no id here"}))
    archives = {"PyPI": buffer.getvalue()}

    with _client(archives) as client:
        report = sync(tmp_path, ecosystems=["PyPI"], client=client)

    assert report.advisories == 1
    assert len(report.skipped) == 1
    assert "no id" in report.skipped[0]


def test_a_failed_download_names_the_ecosystem_and_url(tmp_path: Path) -> None:
    with _client({}) as client, pytest.raises(AdvisorySyncError) as exc_info:
        sync(tmp_path, ecosystems=["PyPI"], client=client)
    message = str(exc_info.value)
    assert "PyPI" in message
    assert "all.zip" in message


def test_a_corrupt_archive_is_reported(tmp_path: Path) -> None:
    with (
        _client({"PyPI": b"not a zip file at all"}) as client,
        pytest.raises(AdvisorySyncError, match="not a readable zip"),
    ):
        sync(tmp_path, ecosystems=["PyPI"], client=client)


def test_an_implausibly_large_export_is_refused(tmp_path: Path) -> None:
    # Unpacking it would exhaust a free-tier worker, and an export that size
    # means something is wrong upstream.
    oversized = b"x" * (MAX_ARCHIVE_BYTES + 1)
    with (
        _client({"PyPI": oversized}) as client,
        pytest.raises(AdvisorySyncError, match="refusing to unpack"),
    ):
        sync(tmp_path, ecosystems=["PyPI"], client=client)


def test_the_export_url_follows_the_documented_layout() -> None:
    assert OSV_EXPORT_BASE.startswith("https://")
    assert "osv-vulnerabilities" in OSV_EXPORT_BASE


def test_two_osv_records_for_one_cve_collapse_to_one_advisory() -> None:
    """GHSA and PYSEC describe the same thing; the CVE names both.

    So the live source must collapse them, and must keep the record that
    carries a repository URL: the fix commit is recovered from it, and
    without a fix commit a reachability verdict is impossible rather than
    merely absent.
    """
    from vexpath_core.advisory.source import _collapse_aliases
    from vexpath_core.enums import Severity, SymbolsStatus
    from vexpath_core.models.advisory import Advisory

    def advisory(repo_url: str | None) -> Advisory:
        return Advisory(
            id="CVE-2024-0001",
            summary="one vulnerability",
            severity=Severity.HIGH,
            repo_url=repo_url,
            affected=(),
            symbols_status=SymbolsStatus.PENDING,
        )

    collapsed = _collapse_aliases((advisory(None), advisory("https://github.com/psf/requests")))

    assert len(collapsed) == 1
    assert collapsed[0].repo_url == "https://github.com/psf/requests"

    # And the preference does not depend on the order they arrive in.
    collapsed = _collapse_aliases((advisory("https://github.com/psf/requests"), advisory(None)))
    assert len(collapsed) == 1
    assert collapsed[0].repo_url == "https://github.com/psf/requests"
