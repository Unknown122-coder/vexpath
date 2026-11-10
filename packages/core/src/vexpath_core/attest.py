"""Sign a VEX document so someone else can check who produced it.

A VEX document says "this vulnerability does not apply to us". That claim is
worth something only if a consumer can establish who made it and that nobody
altered it in transit. Unsigned, it is a text file anybody can write, and the
threat model says so plainly: an uploaded result with no attestation is
"self-reported".

The shape is the one the ecosystem already verifies, so `cosign` and
`in-toto` read these without being taught anything:

- an **in-toto Statement v1** naming what the claim is about (the subject),
  what kind of claim it is (the predicate type) and the claim itself;
- wrapped in a **DSSE envelope**, which signs the payload together with its
  type so a document cannot be re-interpreted as a different kind of document;
- signed either **keylessly through Sigstore**, where the identity is the CI
  workflow that ran and is recorded in a public log, or with a **static key**,
  which is what an air-gapped reviewer can verify with nothing but this
  library.

Three rules, each of which exists because the alternative produces a signature
that means less than it appears to.

**A statement must have a subject.** An attestation about nothing in
particular cannot be matched to an artefact, so a verifier cannot tell whether
it describes the thing in front of them. Building one without a subject raises.

**The signature covers the payload type.** DSSE's pre-authentication encoding
binds both, which is what stops a signed VEX document being presented as a
signed SBOM. Implemented here rather than by concatenation, because getting
that encoding wrong is a vulnerability rather than a bug.

**A failure to sign is never silent.** A caller gets an error and the scan
records no attestation. A pipeline that believes it is signing and is not is
worse off than one that knows it is not.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vexpath_core import __version__ as core_version

#: in-toto Statement version this builds. v1 is the one cosign and the
#: in-toto tooling verify today.
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: DSSE payload type for an in-toto statement. Part of what is signed.
PAYLOAD_TYPE = "application/vnd.in-toto+json"

#: Predicate type for the scan result itself, as distinct from the VEX
#: document. Namespaced under this project because nobody else defines it.
RESULTS_PREDICATE_TYPE = "https://vexpath.dev/attestations/scan-results/v1"


class AttestationError(Exception):
    """Raised when something cannot be signed or verified.

    Always surfaced. A pipeline that believes it signed something and did not
    is worse off than one that knows it did not.
    """


@dataclass(frozen=True, slots=True)
class Subject:
    """What an attestation is about.

    The digest is what a verifier matches against the artefact in front of
    them, so a subject without one is not usable as a subject at all.
    """

    name: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            msg = "a subject needs a name a verifier can match against"
            raise AttestationError(msg)
        digest = self.sha256.strip().lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            msg = f"subject {self.name!r} has {self.sha256!r}, which is not a sha256 digest"
            raise AttestationError(msg)

    def as_json(self) -> dict[str, Any]:
        return {"name": self.name, "digest": {"sha256": self.sha256.strip().lower()}}


def subject_for_file(path: Path, *, name: str | None = None) -> Subject:
    """A subject naming a file on disk, digested as it is now."""
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        msg = f"{path} could not be read to digest it: {exc}"
        raise AttestationError(msg) from exc
    return Subject(name=name or path.name, sha256=digest)


def subject_for_bytes(payload: bytes, name: str) -> Subject:
    """A subject naming something held in memory."""
    return Subject(name=name, sha256=hashlib.sha256(payload).hexdigest())


def build_statement(
    predicate: dict[str, Any],
    predicate_type: str,
    subjects: list[Subject],
) -> dict[str, Any]:
    """Wrap a predicate in an in-toto Statement v1.

    Raises:
        AttestationError: if there is no subject. An attestation about nothing
            in particular cannot be matched to an artefact, so a verifier
            cannot tell whether it describes the thing they are holding.
    """
    if not subjects:
        msg = (
            "an attestation needs at least one subject: without one a verifier "
            "cannot tell whether it describes the artefact in front of them"
        )
        raise AttestationError(msg)
    if not predicate_type.strip():
        msg = "an attestation needs a predicate type, or nothing knows how to read it"
        raise AttestationError(msg)

    return {
        "_type": STATEMENT_TYPE,
        "subject": [subject.as_json() for subject in subjects],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def canonical_payload(statement: dict[str, Any]) -> bytes:
    """Serialise a statement the way it will be signed.

    Sorted keys and no insignificant whitespace, so the bytes a verifier
    recomputes are the bytes that were signed. The envelope carries the
    payload verbatim anyway, but a deterministic encoding means two runs over
    the same results produce the same envelope, which is what lets one be
    diffed against another.
    """
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding.

    ``DSSEv1 <len(type)> <type> <len(payload)> <payload>``, with lengths in
    ASCII decimal. Signing this rather than the payload alone is what binds a
    signature to the *kind* of document it covers, so a signed VEX document
    cannot be presented as a signed SBOM.

    Written out rather than assembled by concatenating strings, because an
    encoding that is almost right here is a vulnerability rather than a bug.
    """
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(type_bytes), type_bytes, len(payload), payload)


@dataclass(frozen=True, slots=True)
class Envelope:
    """A signed DSSE envelope."""

    payload: bytes
    payload_type: str = PAYLOAD_TYPE
    signatures: tuple[dict[str, str], ...] = ()

    def as_json(self) -> dict[str, Any]:
        """The wire form: payload base64-encoded, signatures alongside."""
        return {
            "payloadType": self.payload_type,
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "signatures": [dict(signature) for signature in self.signatures],
        }

    def to_json(self) -> str:
        return json.dumps(self.as_json(), indent=2, sort_keys=True) + "\n"

    @property
    def statement(self) -> dict[str, Any]:
        """The statement inside, parsed.

        Raises:
            AttestationError: if the payload is not a readable statement. An
                envelope whose payload cannot be parsed is not something to
                treat as verified just because a signature checked out.
        """
        try:
            parsed = json.loads(self.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            msg = f"the envelope payload is not readable JSON: {exc}"
            raise AttestationError(msg) from exc
        if not isinstance(parsed, dict):
            msg = "the envelope payload is not a JSON object"
            raise AttestationError(msg)
        return parsed

    @property
    def predicate_type(self) -> str:
        return str(self.statement.get("predicateType") or "")

    @property
    def subjects(self) -> tuple[Subject, ...]:
        found: list[Subject] = []
        for entry in self.statement.get("subject") or []:
            if not isinstance(entry, dict):
                continue
            digest = entry.get("digest")
            if not isinstance(digest, dict) or "sha256" not in digest:
                continue
            found.append(Subject(name=str(entry.get("name") or ""), sha256=str(digest["sha256"])))
        return tuple(found)


def parse_envelope(raw: str | bytes) -> Envelope:
    """Read an envelope from its wire form.

    Raises:
        AttestationError: if it is not a DSSE envelope. Being strict here is
            the point: a file that merely looks like one must not be reported
            as verified.
    """
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        msg = f"not a readable DSSE envelope: {exc}"
        raise AttestationError(msg) from exc
    if not isinstance(document, dict):
        msg = "not a DSSE envelope: the top level is not an object"
        raise AttestationError(msg)

    encoded = document.get("payload")
    payload_type = document.get("payloadType")
    if not isinstance(encoded, str) or not isinstance(payload_type, str):
        msg = "not a DSSE envelope: 'payload' and 'payloadType' are required"
        raise AttestationError(msg)
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        msg = f"the envelope payload is not valid base64: {exc}"
        raise AttestationError(msg) from exc

    signatures = tuple(
        {str(key): str(value) for key, value in signature.items()}
        for signature in (document.get("signatures") or [])
        if isinstance(signature, dict)
    )
    return Envelope(payload=payload, payload_type=payload_type, signatures=signatures)


# --- Static keys ----------------------------------------------------------


def generate_key() -> tuple[bytes, bytes]:
    """A fresh ed25519 keypair, as PEM private and public bytes.

    Ed25519 rather than RSA: the keys are short enough to paste into a secret
    store, signing is fast, and there are no parameters to get wrong.
    """
    private = Ed25519PrivateKey.generate()
    return (
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def key_id(public_pem: bytes) -> str:
    """A short identifier for a public key.

    Lets an envelope say which key signed it when a verifier holds several,
    without putting the key itself in the envelope.
    """
    return hashlib.sha256(public_pem).hexdigest()[:16]


def sign_with_key(statement: dict[str, Any], private_pem: bytes) -> Envelope:
    """Sign a statement with a static ed25519 key.

    This is the path an air-gapped reviewer can verify with nothing but this
    library, and the path the tests use. Keyless signing is the one to prefer
    in CI, because it binds the signature to the workflow that ran rather than
    to a secret somebody has to store.
    """
    private = _load_private(private_pem)
    payload = canonical_payload(statement)
    signature = private.sign(pae(PAYLOAD_TYPE, payload))
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return Envelope(
        payload=payload,
        payload_type=PAYLOAD_TYPE,
        signatures=(
            {
                "sig": base64.b64encode(signature).decode("ascii"),
                "keyid": key_id(public_pem),
            },
        ),
    )


def verify_with_key(envelope: Envelope, public_pem: bytes) -> VerificationResult:
    """Check an envelope against a static public key.

    Returns a result rather than raising on a bad signature: "this does not
    verify" is an answer a caller acts on, whereas a malformed envelope or an
    unreadable key is a mistake in how the check was set up.
    """
    public = _load_public(public_pem)
    expected = key_id(public_pem)

    if not envelope.signatures:
        return VerificationResult(
            verified=False, reason="the envelope carries no signatures at all"
        )

    for signature in envelope.signatures:
        encoded = signature.get("sig")
        if not encoded:
            continue
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            continue
        try:
            public.verify(raw, pae(envelope.payload_type, envelope.payload))
        except InvalidSignature:
            continue
        return VerificationResult(
            verified=True,
            key_id=signature.get("keyid") or expected,
            payload_type=envelope.payload_type,
            predicate_type=envelope.predicate_type,
            subjects=envelope.subjects,
        )

    return VerificationResult(
        verified=False,
        reason=(
            f"no signature in the envelope verifies against this key "
            f"({len(envelope.signatures)} tried). Either it was signed by "
            f"someone else, or the payload changed after signing."
        ),
    )


def _load_private(pem: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as exc:
        msg = f"the signing key is not a readable unencrypted PEM private key: {exc}"
        raise AttestationError(msg) from exc
    if not isinstance(key, Ed25519PrivateKey):
        msg = (
            f"the signing key is {type(key).__name__}; this signs with ed25519, "
            f"so generate one with 'vexpath attest keygen'"
        )
        raise AttestationError(msg)
    return key


def _load_public(pem: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        msg = f"the verification key is not a readable PEM public key: {exc}"
        raise AttestationError(msg) from exc
    if not isinstance(key, Ed25519PublicKey):
        msg = f"the verification key is {type(key).__name__}; this verifies ed25519"
        raise AttestationError(msg)
    return key


# --- What a verification concluded ----------------------------------------


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Whether an envelope checked out, and what it says.

    Carries the identity and the subjects so a caller can apply its own
    constraints. A signature that verifies against *some* key is not the same
    as one that verifies against the key you expected, and a verifier that
    conflates the two is not doing its job.
    """

    verified: bool
    reason: str = ""
    #: Static-key signing: which key. Keyless: empty.
    key_id: str = ""
    #: Keyless signing: the identity in the certificate, usually a workflow
    #: URL, and the issuer that vouched for it.
    identity: str = ""
    issuer: str = ""
    payload_type: str = ""
    predicate_type: str = ""
    subjects: tuple[Subject, ...] = ()
    #: Where the signature came from: ``static-key`` or ``sigstore``.
    method: str = "static-key"
    notes: tuple[str, ...] = field(default=())

    def requires(
        self,
        *,
        predicate_type: str | None = None,
        subject_sha256: str | None = None,
        identity: str | None = None,
        issuer: str | None = None,
    ) -> VerificationResult:
        """Narrow a successful verification with the caller's constraints.

        Checked here rather than left to the caller because every one of these
        is a step somebody forgets, and forgetting any of them turns "this
        signature is valid" into something much weaker than it sounds: valid
        for a different artefact, a different kind of claim, or a different
        signer entirely.
        """
        if not self.verified:
            return self

        if predicate_type is not None and self.predicate_type != predicate_type:
            return self._failed(
                f"the attestation is about {self.predicate_type!r}, not "
                f"{predicate_type!r}, so it does not say what was asked"
            )
        if subject_sha256 is not None:
            wanted = subject_sha256.strip().lower()
            if not any(subject.sha256.lower() == wanted for subject in self.subjects):
                named = ", ".join(subject.name for subject in self.subjects) or "nothing"
                return self._failed(
                    f"the attestation covers {named}, not the artefact with digest "
                    f"{wanted[:16]}..., so it describes something else"
                )
        if identity is not None and self.identity != identity:
            return self._failed(
                f"signed by {self.identity or 'an unstated identity'}, not by {identity}"
            )
        if issuer is not None and self.issuer != issuer:
            return self._failed(
                f"the identity was vouched for by {self.issuer or 'nobody stated'}, not by {issuer}"
            )
        return self

    def _failed(self, reason: str) -> VerificationResult:
        return VerificationResult(
            verified=False,
            reason=reason,
            key_id=self.key_id,
            identity=self.identity,
            issuer=self.issuer,
            payload_type=self.payload_type,
            predicate_type=self.predicate_type,
            subjects=self.subjects,
            method=self.method,
        )

    def summary_line(self) -> str:
        if not self.verified:
            return f"NOT VERIFIED: {self.reason}"
        # An f-string is always truthy, so the fallbacks are ordered on the
        # values themselves rather than on their formatting.
        if self.identity:
            who = self.identity
        elif self.key_id:
            who = f"key {self.key_id}"
        else:
            who = "an unidentified signer"
        covers = ", ".join(subject.name for subject in self.subjects) or "no named subject"
        return f"verified: signed by {who}, covering {covers}, as {self.predicate_type}"


# --- Keyless signing ------------------------------------------------------

#: Why keyless is preferred in CI, in one place so the error can say it.
_KEYLESS_RATIONALE = (
    "Keyless signing binds the signature to the workflow that produced it and "
    "records it in a public transparency log, so there is no long-lived secret "
    "to leak and the identity is something a consumer can check."
)


def sign_keyless(statement: dict[str, Any], *, identity_token: str | None = None) -> Envelope:
    """Sign through Sigstore, using an ambient OIDC credential.

    Intended for CI, where the credential is the workflow's own identity. The
    library is an optional dependency, so its absence is reported as a
    configuration problem rather than a crash.

    Raises:
        AttestationError: if Sigstore is unavailable or signing fails. Never
            falls back to leaving the document unsigned: a pipeline that
            believes it is signing and is not is worse off than one that knows
            it is not.
    """
    try:
        from sigstore.oidc import detect_credential
        from sigstore.sign import SigningContext
    except ImportError as exc:
        msg = (
            f"keyless signing needs the 'sigstore' extra: install "
            f"vexpath-core[sigstore]. {_KEYLESS_RATIONALE}"
        )
        raise AttestationError(msg) from exc

    token = identity_token or detect_credential()
    if not token:
        msg = (
            "no OIDC credential is available, so there is no identity to sign "
            "with. In GitHub Actions grant the job 'id-token: write'. Locally, "
            "sign with a static key instead and expect it to be labelled "
            "developer-signed."
        )
        raise AttestationError(msg)

    payload = canonical_payload(statement)
    try:
        context = SigningContext.production()
        with context.signer(_identity(token)) as signer:
            bundle = signer.sign_dsse(_InTotoPayload(payload))
    except Exception as exc:
        msg = f"keyless signing failed: {type(exc).__name__}: {exc}"
        raise AttestationError(msg) from exc

    return _envelope_from_bundle(bundle, payload)


def _identity(token: str) -> Any:
    from sigstore.oidc import IdentityToken

    return IdentityToken(token)


@dataclass(frozen=True, slots=True)
class _InTotoPayload:
    """Adapter so a raw payload can be handed to sigstore's DSSE signer."""

    payload: bytes

    def _type(self) -> str:
        return PAYLOAD_TYPE


def _envelope_from_bundle(bundle: Any, payload: bytes) -> Envelope:
    """Pull the DSSE envelope out of a Sigstore bundle.

    The bundle holds the certificate and the transparency-log entry as well,
    which a verifier needs; they are kept alongside the signature rather than
    discarded, because without them the keyless signature cannot be checked at
    all.
    """
    try:
        envelope = bundle._inner.dsse_envelope
        signature = base64.b64encode(bytes(envelope.signatures[0].sig)).decode("ascii")
        certificate = base64.b64encode(bundle.signing_certificate.public_bytes_pem()).decode(
            "ascii"
        )
    except Exception as exc:
        msg = f"the signing bundle could not be read: {type(exc).__name__}: {exc}"
        raise AttestationError(msg) from exc

    return Envelope(
        payload=payload,
        payload_type=PAYLOAD_TYPE,
        signatures=({"sig": signature, "cert": certificate},),
    )


def attestation_metadata(envelope: Envelope) -> dict[str, Any]:
    """What a report says about an attestation without verifying it.

    Deliberately separate from verification: describing an envelope and
    believing it are different operations, and a report that blurs them
    teaches readers that a signature's presence is the same as its validity.
    """
    statement = envelope.statement
    return {
        "payload_type": envelope.payload_type,
        "predicate_type": envelope.predicate_type,
        "statement_type": str(statement.get("_type") or ""),
        "subjects": [subject.as_json() for subject in envelope.subjects],
        "signature_count": len(envelope.signatures),
        "keyless": any("cert" in signature for signature in envelope.signatures),
        "tooling": f"vexpath/{core_version}",
        "verified": False,
    }


__all__ = [
    "PAYLOAD_TYPE",
    "RESULTS_PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "AttestationError",
    "Envelope",
    "Subject",
    "VerificationResult",
    "attestation_metadata",
    "build_statement",
    "canonical_payload",
    "generate_key",
    "key_id",
    "pae",
    "parse_envelope",
    "sign_keyless",
    "sign_with_key",
    "subject_for_bytes",
    "subject_for_file",
    "verify_with_key",
]
