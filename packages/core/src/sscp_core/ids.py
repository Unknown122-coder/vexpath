"""ULID generation.

Identifiers are ULIDs rather than UUIDs because they sort by creation time,
which makes ``ORDER BY id`` meaningful for scans and findings and keeps
pagination cheap. The implementation is 30 lines, so it is kept here instead of
adding a dependency.

Layout (128 bits, Crockford base32, 26 characters):

    | 48 bits milliseconds since the Unix epoch | 80 bits randomness |
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime

# Crockford base32: no I, L, O or U, so a ULID cannot be misread aloud.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE = {c: i for i, c in enumerate(_ALPHABET)}

_ULID_LENGTH = 26
_TIMESTAMP_CHARS = 10
_RANDOM_BYTES = 10
_MAX_TIMESTAMP = (1 << 48) - 1


def new_ulid(*, timestamp_ms: int | None = None) -> str:
    """Return a fresh ULID.

    Args:
        timestamp_ms: Milliseconds since the Unix epoch. Defaults to now.
            Pass it explicitly in tests to get reproducible identifiers.
    """
    ms = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    if not 0 <= ms <= _MAX_TIMESTAMP:
        msg = f"timestamp out of ULID range: {ms}"
        raise ValueError(msg)
    value = (ms << 80) | int.from_bytes(os.urandom(_RANDOM_BYTES), "big")
    return _encode(value)


def ulid_timestamp(ulid: str) -> datetime:
    """Return the creation time encoded in a ULID, as an aware UTC datetime."""
    ms = _decode(ulid) >> 80
    return datetime.fromtimestamp(ms / 1000, tz=UTC)


def is_ulid(value: str) -> bool:
    """Return True if ``value`` is a syntactically valid ULID."""
    if len(value) != _ULID_LENGTH:
        return False
    return all(c in _DECODE for c in value.upper())


def _encode(value: int) -> str:
    chars = [""] * _ULID_LENGTH
    for i in range(_ULID_LENGTH - 1, -1, -1):
        chars[i] = _ALPHABET[value & 0x1F]
        value >>= 5
    return "".join(chars)


def _decode(ulid: str) -> int:
    if len(ulid) != _ULID_LENGTH:
        msg = f"a ULID is {_ULID_LENGTH} characters, got {len(ulid)}"
        raise ValueError(msg)
    value = 0
    for char in ulid.upper():
        try:
            value = (value << 5) | _DECODE[char]
        except KeyError as exc:
            msg = f"{char!r} is not a Crockford base32 character"
            raise ValueError(msg) from exc
    return value


__all__ = ["is_ulid", "new_ulid", "ulid_timestamp"]
