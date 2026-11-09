"""Advisory snapshots, which are what make a scan reproducible."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sscp_core.enums import Severity, SymbolsStatus
from sscp_core.models.advisory import Advisory, AdvisorySnapshot
from sscp_core.snapshot import (
    ADVISORIES_FILE,
    SnapshotIntegrityError,
    advisory_source_hash,
    canonical_json,
    read_snapshot,
    snapshot_content_hash,
    summarise,
    write_snapshot,
)


def _advisory(advisory_id: str = "CVE-2024-0001", **overrides: object) -> Advisory:
    defaults: dict[str, object] = {
        "id": advisory_id,
        "summary": "Example",
        "severity": Severity.HIGH,
        "modified_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    return Advisory(**(defaults | overrides))  # type: ignore[arg-type]


# --- The frozen fixture snapshot -------------------------------------------


def test_the_committed_snapshot_verifies(snapshot_dir: Path) -> None:
    metadata, advisories = read_snapshot(snapshot_dir)
    assert metadata.id == "test-snapshot-0001"
    assert len(advisories) == 8
    assert all(advisory.source_sha256 for advisory in advisories)


def test_the_committed_snapshot_covers_the_cases_the_fixtures_need(snapshot_dir: Path) -> None:
    _, advisories = read_snapshot(snapshot_dir)
    by_id = {advisory.id: advisory for advisory in advisories}

    # One withdrawn advisory, so matching can be checked to skip it.
    assert by_id["CVE-2024-FIXTURE-WITHDRAWN"].is_withdrawn

    # One advisory with no symbols, so the under_investigation path is covered.
    assert by_id["CVE-2024-FIXTURE-NOSYMBOLS"].symbols_status is SymbolsStatus.NONE
    assert by_id["CVE-2024-FIXTURE-NOSYMBOLS"].symbols == ()

    # One non-Python ecosystem, for the unsupported-reachability path.
    lodash = by_id["CVE-2021-23337"]
    assert [package.ecosystem for package in lodash.affected] == ["npm"]

    # And a module-level symbol, where an import alone counts as reaching it.
    pyyaml = by_id["CVE-2020-14343"]
    assert any(symbol.kind.value == "module" for symbol in pyyaml.symbols)


def test_fixture_symbols_do_not_claim_to_come_from_real_fix_commits(
    snapshot_dir: Path,
) -> None:
    # The fixture is hand-authored. If a future change starts extracting real
    # symbols, that is a deliberate act and this test should be updated with it.
    _, advisories = read_snapshot(snapshot_dir)
    for advisory in advisories:
        for symbol in advisory.symbols:
            assert symbol.source.value == "curated", symbol.symbol
            assert symbol.fix_commit is None


# --- Hashing ---------------------------------------------------------------


def test_canonical_json_is_stable_against_key_order() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_source_hash_ignores_daily_enrichment() -> None:
    """EPSS changes every day; including it would churn every hash daily."""
    base = _advisory()
    enriched = base.model_copy(update={"epss_score": 0.42, "kev": True})
    assert advisory_source_hash(base) == advisory_source_hash(enriched)


def test_source_hash_ignores_derived_symbols() -> None:
    # Symbols appear later, when patch diffing runs. Their arrival must not
    # make an advisory look like it changed upstream.
    base = _advisory()
    with_status = base.model_copy(update={"symbols_status": SymbolsStatus.EXTRACTED})
    assert advisory_source_hash(base) == advisory_source_hash(with_status)


def test_source_hash_tracks_real_content_changes() -> None:
    base = _advisory()
    assert advisory_source_hash(base) != advisory_source_hash(
        base.model_copy(update={"summary": "Something else"})
    )
    assert advisory_source_hash(base) != advisory_source_hash(
        base.model_copy(update={"severity": Severity.LOW})
    )


def test_snapshot_hash_is_independent_of_sync_order() -> None:
    hashes = ["c" * 64, "a" * 64, "b" * 64]
    assert snapshot_content_hash(hashes) == snapshot_content_hash(sorted(hashes))


# --- Reading and writing ---------------------------------------------------


def test_round_trip(tmp_path: Path) -> None:
    advisories = [_advisory("CVE-2024-0002"), _advisory("CVE-2024-0001")]
    snapshot = AdvisorySnapshot(
        id="round-trip",
        created_at=datetime(2026, 11, 9, tzinfo=UTC),
        content_sha256="0" * 64,
        ecosystems=(),
    )
    stored = write_snapshot(tmp_path, snapshot, advisories)
    assert stored.content_sha256 != "0" * 64

    metadata, loaded = read_snapshot(tmp_path)
    assert metadata.content_sha256 == stored.content_sha256
    # Written sorted by id, so a diff of the file is readable.
    assert [advisory.id for advisory in loaded] == ["CVE-2024-0001", "CVE-2024-0002"]


def test_tampering_is_detected(tmp_path: Path) -> None:
    """A modified advisory corpus changes verdicts, so loading one must fail."""
    snapshot = AdvisorySnapshot(
        id="tamper",
        created_at=datetime(2026, 11, 9, tzinfo=UTC),
        content_sha256="0" * 64,
        ecosystems=(),
    )
    write_snapshot(tmp_path, snapshot, [_advisory()])

    path = tmp_path / ADVISORIES_FILE
    path.write_text(
        path.read_text(encoding="utf-8").replace("Example", "Harmless"), encoding="utf-8"
    )

    with pytest.raises(SnapshotIntegrityError, match="does not match its contents"):
        read_snapshot(tmp_path)

    # Verification can be turned off deliberately, for inspecting a snapshot
    # that is already known to be inconsistent.
    _, advisories = read_snapshot(tmp_path, verify=False)
    assert advisories[0].summary == "Harmless"


def test_a_corrupt_line_names_its_line_number(tmp_path: Path) -> None:
    (tmp_path / "snapshot.json").write_text(
        AdvisorySnapshot(
            id="broken",
            created_at=datetime(2026, 11, 9, tzinfo=UTC),
            content_sha256="0" * 64,
            ecosystems=(),
        ).model_dump_json(),
        encoding="utf-8",
    )
    (tmp_path / ADVISORIES_FILE).write_text('{"id": "ok"}\nnot json at all\n', encoding="utf-8")

    with pytest.raises(SnapshotIntegrityError, match=r":2:"):
        read_snapshot(tmp_path)


def test_a_missing_file_is_reported_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match=r"snapshot\.json is missing"):
        read_snapshot(tmp_path)


def test_summary_counts_symbol_coverage(snapshot_dir: Path) -> None:
    # Symbol coverage is the metric the product's usefulness rests on, so it is
    # recorded in every snapshot rather than computed when someone asks.
    _, advisories = read_snapshot(snapshot_dir)
    counts = summarise(advisories)
    assert counts["PyPI"]["advisories"] == 7
    assert counts["PyPI"]["with_symbols"] == 5
    assert counts["npm"]["with_symbols"] == 0
