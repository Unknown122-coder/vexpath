"""Browser sessions, the OAuth state parameter, and CSRF tokens.

Three secrets with three different jobs, kept in one module because the
reasoning about all three is the same: a value arriving from a browser is
attacker-controlled until something cryptographic says otherwise.

**A session cookie is a bearer credential with a browser attached.** That last
part is the whole difference from an API key: the browser sends it
automatically, on any request to this origin, including one triggered by
another site. So the cookie carries ``HttpOnly`` (a script cannot read it even
if one ever ran), ``SameSite=Lax`` (another site's form POST does not carry
it), and ``Secure`` outside local development. Only the hash is stored, as for
API keys: a database disclosure must not hand over live sessions.

**The OAuth state parameter is not optional.** Without it, an attacker
completes an authorisation flow with their own code against a victim's browser
and the victim ends up logged into the attacker's account. The state here is
signed and time-limited rather than stored, so it needs no table and no
cleanup, and it carries the page the user was trying to reach so the redirect
after login is not a guess.

**The CSRF token is derived from the session, not stored.** It is an HMAC of
the session identifier under the process secret, so it is constant for a
session, useless in any other session, and requires no storage that could fall
out of step with the session itself. Verified in constant time; ``SameSite``
already blocks the cross-site POST and this is the second lock on the same
door, because a future need for ``SameSite=None`` on some endpoint must not
silently remove the only defence.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

#: The cookie's name. Prefixed so it is recognisable in a browser's inspector
#: and cannot collide with anything else on a shared domain.
COOKIE_NAME = "vexpath_session"

#: Bytes of entropy in a session token. The same 256 bits as an API key:
#: guessing is not a threat anybody should have to think about again.
TOKEN_BYTES = 32

#: How long a session lives, absolutely. Long enough that signing in is not a
#: daily chore, short enough that a stolen laptop stops being a live
#: credential within a fortnight.
LIFETIME = timedelta(days=14)

#: How long the OAuth state parameter stays valid. A login that takes longer
#: than ten minutes has been interrupted, and re-issuing the state costs one
#: redirect.
STATE_LIFETIME = timedelta(minutes=10)

#: Separates the parts of a signed value, and is excluded from the base64url
#: alphabet so it can never appear inside one.
_SEPARATOR = "."

#: Domain separation, so a signature produced for one purpose cannot be
#: replayed as the other. Without this, a CSRF token would be a valid state
#: parameter and the two defences would collapse into one.
_STATE_CONTEXT = b"vexpath.oauth.state.v1"
_CSRF_CONTEXT = b"vexpath.csrf.v1"


def now() -> datetime:
    """The current time, always timezone-aware."""
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """A new session: the cookie value, and what to store.

    The secret exists in this object and in the response that sets the cookie,
    and nowhere else. The database gets the hash.
    """

    secret: str
    token_hash: str
    expires_at: datetime

    def __repr__(self) -> str:
        """Never render the token.

        A session object in a traceback would otherwise hand a live credential
        to whoever reads the log.
        """
        return f"IssuedSession(token_hash={self.token_hash[:8]}…, expires_at={self.expires_at!r})"


def issue(*, lifetime: timedelta = LIFETIME, moment: datetime | None = None) -> IssuedSession:
    """Create a session token.

    ``token_urlsafe`` draws from the operating system's random source. Nothing
    about the user, the organisation or the time is encoded in it: a token that
    carried information would invite someone to try changing it.
    """
    secret = secrets.token_urlsafe(TOKEN_BYTES)
    return IssuedSession(
        secret=secret,
        token_hash=hash_token(secret),
        expires_at=(moment or now()) + lifetime,
    )


def hash_token(secret: str) -> str:
    """The stored form of a session token.

    Plain SHA-256, for the same reason as an API key: the token is 256 bits
    from the system random source, so guessing it is not the threat a slow hash
    defends against, and a slow hash here would add latency to every page
    load.
    """
    return hashlib.sha256(secret.strip().encode("utf-8")).hexdigest()


def verify_token(secret: str, stored_hash: str | None) -> bool:
    """Whether a presented token matches a stored hash.

    Compared in constant time, and against a fixed value when no session was
    found, so the time taken does not say whether a session identifier exists.
    """
    candidate = hash_token(secret)
    reference = stored_hash or "0" * 64
    return hmac.compare_digest(candidate, reference) and stored_hash is not None


def is_expired(expires_at: datetime, *, moment: datetime | None = None) -> bool:
    """Whether a session has passed its absolute expiry.

    Checked in the application as well as being enforced by deletion, because
    the deletion is a background job and a job that has not run yet must not
    mean an immortal session.
    """
    return expires_at <= (moment or now())


# --- The OAuth state parameter ---------------------------------------------


def sign_state(secret_key: str, return_to: str, *, moment: datetime | None = None) -> str:
    """A signed, time-limited state parameter carrying where to go next.

    Signed rather than stored. A stored state needs a table, an index and a
    cleanup job, and gains nothing: the only property required is that the
    state coming back is one this process issued recently.

    The return path travels inside the signature, so it cannot be edited into
    an open redirect on the way through the identity provider.
    """
    issued = int((moment or now()).timestamp())
    nonce = secrets.token_urlsafe(16)
    payload = f"{issued}{_SEPARATOR}{nonce}{_SEPARATOR}{_encode(return_to)}"
    return f"{payload}{_SEPARATOR}{_sign(secret_key, _STATE_CONTEXT, payload)}"


def verify_state(secret_key: str, state: str, *, moment: datetime | None = None) -> str | None:
    """The return path from a state parameter, or None if it is not acceptable.

    Returns None for a forged signature, a malformed value and an expired one
    alike. The caller has one remedy for all three -- start the login again --
    so distinguishing them would only tell someone probing which part of their
    forgery to fix.
    """
    parts = state.split(_SEPARATOR)
    if len(parts) != 4:
        return None
    issued_raw, _nonce, encoded_return, signature = parts

    payload = _SEPARATOR.join(parts[:3])
    if not hmac.compare_digest(signature, _sign(secret_key, _STATE_CONTEXT, payload)):
        return None

    try:
        issued = datetime.fromtimestamp(int(issued_raw), tz=UTC)
    except (ValueError, OverflowError, OSError):
        return None
    if (moment or now()) - issued > STATE_LIFETIME:
        return None
    # A clock that has gone backwards, or a timestamp from the future, means
    # something is wrong with the value rather than with the clock.
    if issued > (moment or now()) + timedelta(minutes=1):
        return None

    try:
        return _decode(encoded_return)
    except ValueError:
        return None


# --- CSRF ------------------------------------------------------------------


def csrf_token(secret_key: str, session_id: str) -> str:
    """The token to embed in every form that changes something.

    Derived from the session rather than stored, so there is no second piece
    of state to keep in step, and no way for a valid token to outlive the
    session it belongs to.
    """
    return _sign(secret_key, _CSRF_CONTEXT, session_id)


def verify_csrf(secret_key: str, session_id: str, presented: str | None) -> bool:
    """Whether a submitted token belongs to this session.

    Constant-time, and false for a missing token: a form that forgot to carry
    one must fail, not pass by default. That is the difference between a check
    and a decoration.
    """
    if not presented:
        return False
    return hmac.compare_digest(presented, csrf_token(secret_key, session_id))


# --- Cookie attributes ------------------------------------------------------


def cookie_attributes(*, secure: bool, lifetime: timedelta = LIFETIME) -> dict[str, object]:
    """Keyword arguments for setting the session cookie.

    In one place because each attribute removes a distinct attack and omitting
    any one of them is invisible until it matters:

    ``httponly`` keeps the token out of reach of script, so a content-injection
    bug does not become account takeover. ``samesite="lax"`` means another
    site's form POST arrives without the cookie, which is what stops
    cross-site request forgery at the door. ``secure`` keeps it off plaintext
    HTTP, and is off only where there is no HTTPS to use, which is local
    development. ``path="/"`` because the HTML UI spans the whole origin.
    """
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": secure,
        "path": "/",
        "max_age": int(lifetime.total_seconds()),
    }


def _sign(secret_key: str, context: bytes, payload: str) -> str:
    digest = hmac.new(
        secret_key.encode("utf-8") + context, payload.encode("utf-8"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _encode(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def _decode(value: str) -> str:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")


__all__ = [
    "COOKIE_NAME",
    "LIFETIME",
    "STATE_LIFETIME",
    "TOKEN_BYTES",
    "IssuedSession",
    "cookie_attributes",
    "csrf_token",
    "hash_token",
    "is_expired",
    "issue",
    "now",
    "sign_state",
    "verify_csrf",
    "verify_state",
    "verify_token",
]
