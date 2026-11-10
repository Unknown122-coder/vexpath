"""Encrypting the few secrets that have to be recoverable.

An API key is stored as a hash, which is the right answer because nothing ever
needs the key back: a presented key is hashed and compared. A webhook signing
secret is different in kind. It is a *shared* secret, used to compute an HMAC
on every delivery, so the server has to be able to read it. Hashing it is not
an option, and that is the whole reason this module exists.

The threat it addresses is narrow and worth naming, because encryption whose
threat model is vague is usually decoration. It defends against **disclosure of
the database alone**: a leaked backup, a snapshot copied to the wrong bucket, a
read replica left open, SQL injection. In all of those an attacker holds rows
and not the process environment, and ciphertext is useless to them. It does
**not** defend against an attacker who has the running process, because that
attacker has the key — and pretending otherwise would be the decoration.

The key is derived from ``VEXPATH_SECRET_KEY`` with HKDF and a fixed label, so
there is no second secret to provision, and the label means this key cannot be
confused with the one used to sign a session cookie even though both come from
the same input. The consequence is stated rather than discovered: **rotating
``VEXPATH_SECRET_KEY`` makes stored webhook secrets unreadable**, and the
remedy is to re-issue them. A decryption failure is therefore reported as
"re-issue this secret" rather than as a crash, because after a rotation it is
the expected outcome and not a bug.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#: Domain separation. The same process secret also signs session cookies and
#: CSRF tokens; a derived key with its own label cannot be used in place of
#: either, so a flaw in one does not become a flaw in all three.
_INFO = b"vexpath.secretbox.v1"


class UnreadableSecretError(Exception):
    """A stored secret that cannot be read with the current key.

    Expected after ``VEXPATH_SECRET_KEY`` is rotated, which is why it is its
    own exception with its own remedy rather than a generic failure.
    """


def seal(secret_key: str, plaintext: str) -> str:
    """Encrypt a value for storage.

    Returns a URL-safe token, so the column is ordinary text and nothing in
    the stack has to care that it is ciphertext.
    """
    return Fernet(_key(secret_key)).encrypt(plaintext.encode("utf-8")).decode("ascii")


def unseal(secret_key: str, token: str) -> str:
    """Decrypt a stored value.

    Raises:
        UnreadableSecretError: if the token was written under a different key or
            has been tampered with. Fernet authenticates, so a modified
            ciphertext fails here rather than decrypting to something else --
            which matters when the plaintext is about to be used to sign a
            message somebody else will trust.
    """
    try:
        return Fernet(_key(secret_key)).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as exc:
        msg = (
            "this secret cannot be read with the current VEXPATH_SECRET_KEY. "
            "If the key was rotated, re-issue the secret; the old value cannot "
            "be recovered"
        )
        raise UnreadableSecretError(msg) from exc


def _key(secret_key: str) -> bytes:
    """A Fernet key derived from the process secret.

    HKDF rather than a plain hash: the process secret may be any length and
    any entropy, and HKDF is the construction built for turning such an input
    into a fixed-length key without assuming it was uniform to begin with.
    """
    if not secret_key:
        msg = "VEXPATH_SECRET_KEY is empty, so nothing can be encrypted"
        raise UnreadableSecretError(msg)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        # No salt. A salt would have to be stored and shared to be any use,
        # and the domain-separation label is what this derivation actually
        # needs: the input is already a secret rather than a password.
        salt=None,
        info=_INFO,
    ).derive(secret_key.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


__all__ = ["UnreadableSecretError", "seal", "unseal"]
