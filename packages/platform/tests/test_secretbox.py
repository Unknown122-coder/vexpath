"""Encryption of the secrets that have to be recoverable.

A webhook signing secret cannot be hashed, because an HMAC needs it back. So
it is encrypted, and these tests pin the two things that make that worth
doing: ciphertext is useless without the process secret, and a tampered
ciphertext fails rather than decrypting to something else — which matters when
the plaintext is about to sign a message somebody else will trust.

The third test is the one somebody will be glad of: rotating the process
secret makes stored values unreadable, and the error says to re-issue them
rather than looking like corruption.
"""

from __future__ import annotations

import pytest

from vexpath_platform import secretbox

KEY = "a-process-secret-for-tests"
OTHER_KEY = "a-different-process-secret"
PLAINTEXT = "whsec_abcdefghijklmnopqrstuvwxyz"


def test_a_value_round_trips() -> None:
    sealed = secretbox.seal(KEY, PLAINTEXT)
    assert secretbox.unseal(KEY, sealed) == PLAINTEXT


def test_the_ciphertext_does_not_contain_the_plaintext() -> None:
    assert PLAINTEXT not in secretbox.seal(KEY, PLAINTEXT)


def test_sealing_twice_produces_different_ciphertext() -> None:
    # Fernet carries a random IV, so two rows holding the same secret do not
    # look alike -- otherwise a database reader could tell which webhooks
    # share a secret without decrypting anything.
    assert secretbox.seal(KEY, PLAINTEXT) != secretbox.seal(KEY, PLAINTEXT)


def test_another_key_cannot_read_it() -> None:
    sealed = secretbox.seal(KEY, PLAINTEXT)
    with pytest.raises(secretbox.UnreadableSecretError, match="re-issue"):
        secretbox.unseal(OTHER_KEY, sealed)


def test_a_rotated_process_secret_says_what_to_do() -> None:
    sealed = secretbox.seal(KEY, PLAINTEXT)
    with pytest.raises(secretbox.UnreadableSecretError) as caught:
        secretbox.unseal("rotated-secret", sealed)
    # The expected outcome after a rotation, not a bug, so the message is a
    # remedy rather than a failure.
    assert "VEXPATH_SECRET_KEY" in str(caught.value)
    assert "cannot be recovered" in str(caught.value)


def test_tampered_ciphertext_is_refused_rather_than_decrypted() -> None:
    sealed = secretbox.seal(KEY, PLAINTEXT)
    # Flip a character in the middle. Fernet authenticates, so this fails
    # here; without authentication it could decrypt to a different secret and
    # the server would sign a delivery with it.
    tampered = sealed[:30] + ("A" if sealed[30] != "A" else "B") + sealed[31:]
    with pytest.raises(secretbox.UnreadableSecretError):
        secretbox.unseal(KEY, tampered)


def test_nonsense_is_refused() -> None:
    for candidate in ("", "not-a-token", "###"):
        with pytest.raises(secretbox.UnreadableSecretError):
            secretbox.unseal(KEY, candidate)


def test_an_empty_process_secret_is_refused() -> None:
    # Better than deriving a key from nothing and encrypting with it, which
    # would be encryption anybody could undo.
    with pytest.raises(secretbox.UnreadableSecretError, match="empty"):
        secretbox.seal("", PLAINTEXT)


def test_the_derived_key_is_domain_separated() -> None:
    """The same process secret also signs cookies and CSRF tokens.

    Asserted indirectly: a value sealed here must not be readable by a
    derivation with a different label. There is no second labelled derivation
    to compare against in this module, so the check is that the Fernet key is
    not the raw secret -- which is what would make the three uses one key.
    """
    sealed = secretbox.seal(KEY, PLAINTEXT)
    import base64

    from cryptography.fernet import Fernet, InvalidToken

    raw = base64.urlsafe_b64encode(KEY.encode("utf-8").ljust(32, b"\0")[:32])
    with pytest.raises((InvalidToken, ValueError)):
        Fernet(raw).decrypt(sealed.encode("ascii"))
