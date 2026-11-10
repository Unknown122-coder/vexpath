"""Session tokens, the OAuth state parameter and CSRF tokens.

These are the three places where a value arriving from a browser is trusted
only because something cryptographic vouched for it, so the tests are mostly
about what must be refused. A signature check that accepts a forgery fails
silently and forever.
"""

from __future__ import annotations

import base64
from datetime import timedelta

from vexpath_platform import sessions

SECRET = "a-secret-that-is-only-for-tests"
OTHER_SECRET = "a-different-secret"


# --- Session tokens ---------------------------------------------------------


def test_a_session_token_is_not_stored_in_the_clear() -> None:
    issued = sessions.issue()
    # The hash is what a database holds. A disclosure of it must not hand
    # anybody a working session.
    assert issued.token_hash != issued.secret
    assert len(issued.token_hash) == 64
    assert sessions.hash_token(issued.secret) == issued.token_hash


def test_two_sessions_never_collide() -> None:
    tokens = {sessions.issue().secret for _ in range(200)}
    assert len(tokens) == 200


def test_a_token_verifies_against_its_own_hash_and_nothing_else() -> None:
    issued = sessions.issue()
    other = sessions.issue()
    assert sessions.verify_token(issued.secret, issued.token_hash)
    assert not sessions.verify_token(issued.secret, other.token_hash)


def test_verification_fails_closed_when_no_session_was_found() -> None:
    issued = sessions.issue()
    # None means "no such session". It must be false, and it must still do the
    # comparison: a lookup that returns early tells a prober, by timing,
    # which session identifiers exist.
    assert not sessions.verify_token(issued.secret, None)


def test_an_issued_session_repr_hides_the_token() -> None:
    issued = sessions.issue()
    assert issued.secret not in repr(issued)


def test_expiry_is_absolute() -> None:
    issued = sessions.issue(lifetime=timedelta(seconds=-1))
    assert sessions.is_expired(issued.expires_at)
    fresh = sessions.issue()
    assert not sessions.is_expired(fresh.expires_at)


# --- The OAuth state parameter ---------------------------------------------


def test_state_round_trips_the_return_path() -> None:
    state = sessions.sign_state(SECRET, "/app/keys")
    assert sessions.verify_state(SECRET, state) == "/app/keys"


def test_state_signed_with_another_key_is_refused() -> None:
    state = sessions.sign_state(OTHER_SECRET, "/app")
    # Without this check an attacker completes a flow with their own
    # authorisation code in a victim's browser, and the victim ends up signed
    # into the attacker's account.
    assert sessions.verify_state(SECRET, state) is None


def test_an_edited_return_path_is_refused() -> None:
    state = sessions.sign_state(SECRET, "/app")
    issued, nonce, _path, signature = state.split(".")
    # Encoded the way the module does, rather than by calling into it: the
    # forgery has to be built the way an attacker would.
    elsewhere = base64.urlsafe_b64encode(b"//evil.example").decode("ascii").rstrip("=")
    forged = ".".join([issued, nonce, elsewhere, signature])
    # The destination travels inside the signature, so it cannot be turned
    # into an open redirect while out of this application's hands.
    assert sessions.verify_state(SECRET, forged) is None


def test_an_expired_state_is_refused() -> None:
    past = sessions.now() - sessions.STATE_LIFETIME - timedelta(seconds=1)
    state = sessions.sign_state(SECRET, "/app", moment=past)
    assert sessions.verify_state(SECRET, state) is None


def test_a_state_from_the_future_is_refused() -> None:
    ahead = sessions.now() + timedelta(hours=1)
    state = sessions.sign_state(SECRET, "/app", moment=ahead)
    # A timestamp from the future means something is wrong with the value
    # rather than with the clock.
    assert sessions.verify_state(SECRET, state) is None


def test_malformed_state_is_refused_rather_than_raising() -> None:
    for candidate in ("", "nonsense", "a.b.c", "a.b.c.d.e", "1.2.3.4"):
        assert sessions.verify_state(SECRET, candidate) is None


def test_two_states_issued_together_differ() -> None:
    # A nonce, so an issued state cannot be recognised as a repeat of an
    # earlier one by anybody watching the redirect.
    assert sessions.sign_state(SECRET, "/app") != sessions.sign_state(SECRET, "/app")


# --- CSRF -------------------------------------------------------------------


def test_a_csrf_token_belongs_to_one_session() -> None:
    mine = sessions.csrf_token(SECRET, "session-one")
    theirs = sessions.csrf_token(SECRET, "session-two")
    assert mine != theirs
    assert sessions.verify_csrf(SECRET, "session-one", mine)
    # A token lifted from another session is the whole attack this prevents.
    assert not sessions.verify_csrf(SECRET, "session-one", theirs)


def test_a_missing_csrf_token_fails() -> None:
    # A form that forgot to carry one must break, not pass by default. That is
    # the difference between a check and a decoration.
    assert not sessions.verify_csrf(SECRET, "session", None)
    assert not sessions.verify_csrf(SECRET, "session", "")


def test_a_csrf_token_is_not_a_valid_state_parameter() -> None:
    token = sessions.csrf_token(SECRET, "session")
    # Domain separation. Without it the two defences would be one secret used
    # twice, and a value harvested from a form would work in the sign-in flow.
    assert sessions.verify_state(SECRET, token) is None


# --- Cookie attributes ------------------------------------------------------


def test_the_cookie_is_not_reachable_from_script_or_another_site() -> None:
    attributes = sessions.cookie_attributes(secure=True)
    assert attributes["httponly"] is True
    assert attributes["samesite"] == "lax"
    assert attributes["secure"] is True
    assert attributes["path"] == "/"


def test_the_cookie_can_be_sent_over_plain_http_only_when_asked() -> None:
    # Off for local development, where there is no HTTPS to use, and nowhere
    # else: a session cookie on plaintext HTTP is a session anybody on the
    # network can take.
    assert sessions.cookie_attributes(secure=False)["secure"] is False
