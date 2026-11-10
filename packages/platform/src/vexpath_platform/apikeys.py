"""Issue and check API keys.

A key is how a CI job proves which organisation it belongs to. Everything
about its handling follows from one fact: the key is a bearer credential, so
whoever holds it is the organisation as far as this system can tell.

**The secret is never stored.** Only its SHA-256, and the key is shown once at
creation. A disclosure of the database hands over no working credentials,
which is the difference between an embarrassing incident and a breach of every
customer at once.

**A plain hash, deliberately, not bcrypt or argon2.** Those exist to make
guessing a human-chosen password expensive. This secret is 256 bits from the
system random source, so guessing is not the threat and a slow hash would only
add latency to every request. The threat is the secret being stored at all,
which is what hashing addresses.

**The prefix is public and the rest is not.** A key reads
``vexpath_live_<token>``, and the first few characters are stored in the clear
so a dashboard can say which key is which. Secret scanners also look for that
prefix, which is why it is a fixed, recognisable string rather than something
compact.

**Verification is constant-time and says nothing about why it failed.** A
caller learns that the key does not work, never whether it was unknown,
revoked or malformed. Each of those would narrow a search for someone probing.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

# The *format* of a key lives in the shared package, because the command-line
# tool has to recognise one and show a safe prefix of one, and it must not
# depend on this server package to do it (see vexpath_core.keyformat).
# Re-exported here so every server call site reads as it did before.
from vexpath_core.keyformat import (
    KEY_PREFIX,
    VISIBLE_SUFFIX,
    display_prefix,
    looks_like_key,
)

#: Bytes of randomness in the secret. 256 bits: guessing is not a threat worth
#: modelling at that size, which is what lets the hash be a plain one.
TOKEN_BYTES = 32


class ApiKeyError(Exception):
    """Raised when a key cannot be issued."""


@dataclass(frozen=True, slots=True)
class IssuedKey:
    """A freshly minted key.

    The secret is in here exactly once, on its way to being shown to a person
    and then forgotten. Nothing stores it, including this object: it is not
    written to a log, a database or a response body a second time.
    """

    secret: str
    key_hash: str
    prefix: str

    def __repr__(self) -> str:
        """Hide the secret from any accidental rendering.

        A key that appears in a traceback, a log line or a debugger session
        transcript has leaked. Tracebacks are the common case, because they
        are produced exactly when something is going wrong and attention is
        elsewhere.
        """
        return f"IssuedKey(prefix={self.prefix!r}, secret='***')"


def issue() -> IssuedKey:
    """Mint a key.

    Returns the secret to show once, the hash to store, and the prefix to
    display later.
    """
    token = secrets.token_urlsafe(TOKEN_BYTES)
    secret = f"{KEY_PREFIX}{token}"
    return IssuedKey(secret=secret, key_hash=hash_key(secret), prefix=display_prefix(secret))


def hash_key(secret: str) -> str:
    """The stored form of a key."""
    return hashlib.sha256(secret.strip().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class StoredKey:
    """What the database holds about a key, for verification."""

    id: str
    org_id: str
    key_hash: str
    revoked_at: datetime | None = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


def verify(secret: str, stored: StoredKey | None) -> bool:
    """Whether this secret is this key, and the key still works.

    Compared with ``hmac.compare_digest`` so the time taken does not depend on
    how much of the hash matched. The comparison runs even when no key was
    found, against a fixed value, so a request with an unknown key takes the
    same time as one with a known key and a wrong secret. Otherwise the timing
    tells an attacker which identifiers exist.
    """
    candidate = hash_key(secret)
    # A fixed stand-in when nothing was found, so the work is identical.
    expected = stored.key_hash if stored is not None else "0" * 64
    matches = hmac.compare_digest(candidate, expected)
    return bool(matches and stored is not None and not stored.is_revoked)


def bearer_token(header: str | None) -> str:
    """Pull a token out of an Authorization header.

    Returns an empty string for anything that is not a bearer header, rather
    than raising, because an absent or malformed header is an ordinary
    unauthenticated request and not an error worth a stack trace.
    """
    if not header:
        return ""
    scheme, _, token = header.partition(" ")
    if scheme.strip().lower() != "bearer":
        return ""
    return token.strip()


def now() -> datetime:
    """The clock, in one place, so a test can see what was recorded."""
    return datetime.now(UTC)


__all__ = [
    "KEY_PREFIX",
    "TOKEN_BYTES",
    "VISIBLE_SUFFIX",
    "ApiKeyError",
    "IssuedKey",
    "StoredKey",
    "bearer_token",
    "display_prefix",
    "hash_key",
    "issue",
    "looks_like_key",
    "now",
    "verify",
]
