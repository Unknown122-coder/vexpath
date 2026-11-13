"""Fetching the published corpus.

The corpus is what makes a finding clearable: OSV says a package is affected,
it does not say which functions the fix changed. Without one, nearly every
finding comes back ``symbols_unknown`` -- honest, and useless. Building one is
hours of cloning upstream repositories and produces the same answer for
everybody, so it is published and collected rather than rebuilt.

These exercise the real download code against recorded bytes. The client is
injectable for exactly that reason: a test that mocks the function under test
proves nothing about it.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import httpx
import pytest

from vexpath import corpus
from vexpath.sources import snapshot_directory
from vexpath_core.snapshot import ADVISORIES_FILE, SNAPSHOT_METADATA_FILE


def _built_corpus(tmp_path: Path) -> tuple[bytes, bytes]:
    """A real snapshot, built by the real writer, as published bytes."""
    from datetime import UTC, datetime

    from vexpath_core.enums import (
        Confidence,
        Severity,
        SymbolKind,
        SymbolSource,
        SymbolsStatus,
    )
    from vexpath_core.models.advisory import Advisory, AdvisorySnapshot, VulnerableSymbol
    from vexpath_core.snapshot import write_snapshot

    advisory = Advisory(
        id="CVE-2026-0001",
        summary="a problem",
        severity=Severity.HIGH,
        symbols_status=SymbolsStatus.EXTRACTED,
        affected=(),
        symbols=(
            VulnerableSymbol(
                advisory_id="CVE-2026-0001",
                ecosystem="PyPI",
                package_name="lib",
                symbol="lib.danger",
                kind=SymbolKind.FUNCTION,
                source=SymbolSource.FIX_COMMIT,
                confidence=Confidence.HIGH,
            ),
        ),
    )
    source = tmp_path / "built"
    # The writer fills in the content hash and the counts, which is what makes
    # this a real snapshot rather than a file shaped like one.
    write_snapshot(
        source,
        AdvisorySnapshot(
            id="published-1",
            created_at=datetime(2026, 11, 13, tzinfo=UTC),
            content_sha256="0" * 64,
            core_version="0.0.0",
            ecosystems=["PyPI"],
            counts={},
        ),
        [advisory],
    )
    metadata = (source / SNAPSHOT_METADATA_FILE).read_bytes()
    advisories = gzip.compress((source / ADVISORIES_FILE).read_bytes())
    return metadata, advisories


def _client(metadata: bytes, advisories: bytes, *, status: int = 200) -> httpx.Client:
    def handle(request: httpx.Request) -> httpx.Response:
        body = metadata if request.url.path.endswith("snapshot.json") else advisories
        return httpx.Response(status, content=body)

    return httpx.Client(transport=httpx.MockTransport(handle))


def test_a_published_corpus_is_downloaded_and_verified(tmp_path: Path) -> None:
    metadata, advisories = _built_corpus(tmp_path)
    destination = tmp_path / "cache"

    with _client(metadata, advisories) as client:
        where, count, symbols = corpus.pull(
            destination, base_url="https://example.test/corpus", client=client
        )

    assert where == destination
    assert count == 1
    assert symbols == 1
    assert (destination / SNAPSHOT_METADATA_FILE).is_file()


def test_a_corpus_that_does_not_match_its_hash_is_refused(tmp_path: Path) -> None:
    """The check that makes downloading one acceptable at all.

    A substituted corpus changes verdicts: drop the symbols for an advisory
    and every project using that package is quietly cleared. So the hash is
    recomputed over the records and compared with what the snapshot claims,
    and a mismatch is fatal rather than a degraded mode.
    """
    metadata, advisories = _built_corpus(tmp_path)
    tampered = json.loads(metadata)
    tampered["content_sha256"] = "0" * 64

    with (
        _client(json.dumps(tampered).encode(), advisories) as client,
        pytest.raises(corpus.CorpusError),
    ):
        corpus.pull(tmp_path / "cache", base_url="https://example.test/corpus", client=client)


def test_a_failed_download_does_not_replace_a_working_corpus(tmp_path: Path) -> None:
    """Downloaded to a temporary directory and moved only once it verifies.

    Somebody running `advisory pull` on a flaky connection must not end up
    worse off than before they ran it.
    """
    metadata, advisories = _built_corpus(tmp_path)
    destination = tmp_path / "cache"

    with _client(metadata, advisories) as client:
        corpus.pull(destination, base_url="https://example.test/corpus", client=client)
    existing = (destination / SNAPSHOT_METADATA_FILE).read_bytes()

    tampered = json.loads(metadata)
    tampered["content_sha256"] = "0" * 64
    with (
        _client(json.dumps(tampered).encode(), advisories) as client,
        pytest.raises(corpus.CorpusError),
    ):
        corpus.pull(destination, base_url="https://example.test/corpus", client=client)

    assert (destination / SNAPSHOT_METADATA_FILE).read_bytes() == existing


def test_a_missing_corpus_says_what_to_do_instead(tmp_path: Path) -> None:
    metadata, advisories = _built_corpus(tmp_path)
    with (
        _client(metadata, advisories, status=404) as client,
        pytest.raises(corpus.CorpusError, match="advisory sync"),
    ):
        corpus.pull(tmp_path / "cache", base_url="https://example.test/corpus", client=client)


def test_a_downloaded_corpus_is_found_without_being_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the whole feature: it works with no flag and no variable.

    A new user runs `advisory pull` once and every command afterwards is
    reproducible and offline, without being told where anything is.
    """
    metadata, advisories = _built_corpus(tmp_path)
    cache = tmp_path / "home"
    monkeypatch.setenv("VEXPATH_CACHE_DIR", str(cache))
    monkeypatch.delenv("VEXPATH_ADVISORY_SNAPSHOT_DIR", raising=False)

    assert snapshot_directory() is None

    with _client(metadata, advisories) as client:
        corpus.pull(base_url="https://example.test/corpus", client=client)

    assert snapshot_directory() == cache / "corpus"


def test_what_the_caller_asked_for_beats_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cache that is merely present never overrides an explicit choice."""
    metadata, advisories = _built_corpus(tmp_path)
    cache = tmp_path / "home"
    monkeypatch.setenv("VEXPATH_CACHE_DIR", str(cache))
    monkeypatch.delenv("VEXPATH_ADVISORY_SNAPSHOT_DIR", raising=False)
    with _client(metadata, advisories) as client:
        corpus.pull(base_url="https://example.test/corpus", client=client)

    explicit = tmp_path / "elsewhere"
    assert snapshot_directory(explicit) == explicit

    monkeypatch.setenv("VEXPATH_ADVISORY_SNAPSHOT_DIR", str(tmp_path / "built"))
    assert snapshot_directory() == tmp_path / "built"
