"""ULID generation."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sscp_core.ids import is_ulid, new_ulid, ulid_timestamp


def test_ulid_has_the_canonical_shape() -> None:
    ulid = new_ulid()
    assert len(ulid) == 26
    assert is_ulid(ulid)
    # Crockford base32 excludes I, L, O and U so that an identifier read aloud
    # cannot be transcribed wrongly.
    assert not set(ulid) & set("ILOU")


def test_ulids_sort_by_creation_time() -> None:
    earlier = new_ulid(timestamp_ms=1_700_000_000_000)
    later = new_ulid(timestamp_ms=1_700_000_001_000)
    # Lexical order matching time order is the whole reason for choosing ULIDs
    # over UUIDs: ORDER BY id is meaningful and pagination stays cheap.
    assert earlier < later


def test_timestamp_round_trips() -> None:
    instant = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
    ms = int(instant.timestamp() * 1000)
    assert ulid_timestamp(new_ulid(timestamp_ms=ms)) == instant


def test_same_millisecond_still_produces_distinct_ids() -> None:
    ids = {new_ulid(timestamp_ms=1_700_000_000_000) for _ in range(500)}
    assert len(ids) == 500


def test_invalid_input_is_rejected() -> None:
    assert not is_ulid("too-short")
    assert not is_ulid("I" * 26)  # I is not in the alphabet
    with pytest.raises(ValueError, match="26 characters"):
        ulid_timestamp("nope")
    with pytest.raises(ValueError, match="out of ULID range"):
        new_ulid(timestamp_ms=-1)
