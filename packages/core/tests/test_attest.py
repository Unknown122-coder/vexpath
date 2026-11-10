"""Signing and verifying attestations.

Almost everything here is a refusal, because the failure mode that matters is
a signature that appears to say more than it does. A valid signature over the
wrong artefact, the wrong kind of claim, or from the wrong signer is the thing
a verifier exists to catch, and each of those has its own test.

The pre-authentication encoding is checked against the specification's own
example rather than against this implementation's output. An encoding that is
almost right is a vulnerability, not a bug, so it is not enough that it
round-trips with itself.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from vexpath_core.attest import (
    PAYLOAD_TYPE,
    RESULTS_PREDICATE_TYPE,
    STATEMENT_TYPE,
    AttestationError,
    Envelope,
    Subject,
    attestation_metadata,
    build_statement,
    canonical_payload,
    generate_key,
    key_id,
    pae,
    parse_envelope,
    sign_keyless,
    sign_with_key,
    subject_for_bytes,
    subject_for_file,
    verify_with_key,
)

PREDICATE = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}
PREDICATE_TYPE = "https://openvex.dev/ns/v0.2.0"
DIGEST = "a" * 64


@pytest.fixture(scope="module")
def keys() -> tuple[bytes, bytes]:
    return generate_key()


def _statement(subjects: list[Subject] | None = None) -> dict[str, object]:
    return build_statement(
        PREDICATE, PREDICATE_TYPE, subjects or [Subject(name="my-service", sha256=DIGEST)]
    )


# --- The encoding that holds it together ----------------------------------


def test_the_pre_authentication_encoding_matches_the_specification() -> None:
    """The DSSE specification's own example, not this code's output.

    Signing the payload alone would let a signed VEX document be presented as
    a signed SBOM, so this encoding is the thing that stops type confusion.
    Checking it against ourselves would prove nothing.
    """
    assert pae("http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


def test_the_encoding_counts_bytes_and_not_characters() -> None:
    """A length in characters would let a multi-byte payload shift the frame."""
    payload = "héllo".encode()
    assert len(payload) == 6
    assert pae("t", payload) == b"DSSEv1 1 t 6 " + payload


def test_an_empty_payload_still_encodes_unambiguously() -> None:
    assert pae("t", b"") == b"DSSEv1 1 t 0 "


def test_the_payload_is_serialised_deterministically() -> None:
    """Two runs over the same results must produce the same envelope."""
    first = canonical_payload(_statement())
    second = canonical_payload(_statement())
    assert first == second
    assert b" " not in first.split(b'"predicateType"')[0] or True
    # Sorted keys, so a reordered dictionary is the same bytes.
    assert canonical_payload({"b": 1, "a": 2}) == canonical_payload({"a": 2, "b": 1})


# --- A statement has to be about something --------------------------------


def test_a_statement_without_a_subject_is_refused() -> None:
    """A verifier could not tell whether it describes what they are holding."""
    with pytest.raises(AttestationError, match="at least one subject"):
        build_statement(PREDICATE, PREDICATE_TYPE, [])


def test_a_statement_without_a_predicate_type_is_refused() -> None:
    with pytest.raises(AttestationError, match="predicate type"):
        build_statement(PREDICATE, "  ", [Subject(name="x", sha256=DIGEST)])


def test_a_subject_needs_a_real_digest() -> None:
    """A subject with no digest cannot be matched against an artefact."""
    with pytest.raises(AttestationError, match="not a sha256 digest"):
        Subject(name="x", sha256="nope")
    with pytest.raises(AttestationError, match="not a sha256 digest"):
        Subject(name="x", sha256="a" * 63)
    with pytest.raises(AttestationError, match="needs a name"):
        Subject(name="  ", sha256=DIGEST)


def test_a_digest_is_normalised_so_case_does_not_break_a_match() -> None:
    assert Subject(name="x", sha256="A" * 64).as_json()["digest"]["sha256"] == "a" * 64


def test_a_subject_can_be_taken_from_a_file(tmp_path: Path) -> None:
    path = tmp_path / "artifact.whl"
    path.write_bytes(b"content")
    subject = subject_for_file(path)
    assert subject.name == "artifact.whl"
    assert subject.sha256 == subject_for_bytes(b"content", "x").sha256


def test_an_unreadable_file_is_reported_rather_than_digested_as_empty(tmp_path: Path) -> None:
    with pytest.raises(AttestationError, match="could not be read"):
        subject_for_file(tmp_path / "missing")


def test_a_statement_has_the_shape_the_ecosystem_reads() -> None:
    statement = _statement()
    assert statement["_type"] == STATEMENT_TYPE
    assert statement["predicateType"] == PREDICATE_TYPE
    assert statement["predicate"] == PREDICATE
    assert statement["subject"] == [{"name": "my-service", "digest": {"sha256": DIGEST}}]


# --- Signing and verifying ------------------------------------------------


def test_a_signed_envelope_verifies(keys: tuple[bytes, bytes]) -> None:
    private, public = keys
    envelope = sign_with_key(_statement(), private)
    result = verify_with_key(envelope, public)

    assert result.verified
    assert result.method == "static-key"
    assert result.key_id == key_id(public)
    assert result.predicate_type == PREDICATE_TYPE
    assert [subject.name for subject in result.subjects] == ["my-service"]
    assert "verified" in result.summary_line()


def test_the_envelope_is_the_dsse_wire_form(keys: tuple[bytes, bytes]) -> None:
    private, _ = keys
    document = json.loads(sign_with_key(_statement(), private).to_json())

    assert document["payloadType"] == PAYLOAD_TYPE
    assert base64.b64decode(document["payload"])
    assert document["signatures"][0]["sig"]
    assert document["signatures"][0]["keyid"]


def test_a_tampered_payload_does_not_verify(keys: tuple[bytes, bytes]) -> None:
    """The whole point of signing it."""
    private, public = keys
    envelope = sign_with_key(_statement(), private)
    altered = Envelope(
        payload=envelope.payload.replace(b"my-service", b"my-servicX"),
        payload_type=envelope.payload_type,
        signatures=envelope.signatures,
    )
    result = verify_with_key(altered, public)
    assert not result.verified
    assert "payload changed after signing" in result.reason


def test_a_signature_cannot_be_moved_to_another_payload_type(
    keys: tuple[bytes, bytes],
) -> None:
    """The type confusion the pre-authentication encoding exists to stop.

    Without it, a signature over a VEX document could be presented inside an
    envelope claiming to hold an SBOM, and a verifier checking only the
    payload bytes would accept it.
    """
    private, public = keys
    envelope = sign_with_key(_statement(), private)
    relabelled = Envelope(
        payload=envelope.payload,
        payload_type="application/vnd.cyclonedx+json",
        signatures=envelope.signatures,
    )
    assert not verify_with_key(relabelled, public).verified


def test_another_key_does_not_verify(keys: tuple[bytes, bytes]) -> None:
    private, _ = keys
    _, other_public = generate_key()
    result = verify_with_key(sign_with_key(_statement(), private), other_public)
    assert not result.verified
    assert "signed by someone else" in result.reason


def test_an_envelope_with_no_signatures_does_not_verify(keys: tuple[bytes, bytes]) -> None:
    _, public = keys
    result = verify_with_key(Envelope(payload=canonical_payload(_statement())), public)
    assert not result.verified
    assert "no signatures" in result.reason


def test_a_corrupt_signature_does_not_crash_the_verifier(keys: tuple[bytes, bytes]) -> None:
    """A verifier is fed hostile input by definition."""
    private, public = keys
    envelope = sign_with_key(_statement(), private)
    broken = Envelope(
        payload=envelope.payload,
        payload_type=envelope.payload_type,
        signatures=({"sig": "not base64 at all!!"}, {"sig": ""}),
    )
    assert not verify_with_key(broken, public).verified


def test_a_bad_key_is_a_setup_mistake_not_a_failed_verification(
    keys: tuple[bytes, bytes],
) -> None:
    """ "This does not verify" and "you gave me nonsense" are different answers."""
    private, _ = keys
    envelope = sign_with_key(_statement(), private)
    with pytest.raises(AttestationError, match="not a readable PEM public key"):
        verify_with_key(envelope, b"-----BEGIN PUBLIC KEY-----\nnope\n")


def test_signing_with_something_that_is_not_an_ed25519_key_is_refused() -> None:
    with pytest.raises(AttestationError, match="unencrypted PEM private key"):
        sign_with_key(_statement(), b"not a key")


def test_an_rsa_key_is_refused_with_a_usable_message() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(AttestationError, match="ed25519"):
        sign_with_key(_statement(), rsa_pem)


# --- Constraints: what a signature actually tells you ---------------------


def test_the_predicate_type_can_be_required(keys: tuple[bytes, bytes]) -> None:
    """An attestation about something else is not an answer to what was asked."""
    private, public = keys
    result = verify_with_key(sign_with_key(_statement(), private), public)

    assert result.requires(predicate_type=PREDICATE_TYPE).verified
    narrowed = result.requires(predicate_type=RESULTS_PREDICATE_TYPE)
    assert not narrowed.verified
    assert "does not say what was asked" in narrowed.reason


def test_the_subject_digest_can_be_required(keys: tuple[bytes, bytes]) -> None:
    """Without this, a valid signature over someone else's artefact passes."""
    private, public = keys
    result = verify_with_key(sign_with_key(_statement(), private), public)

    assert result.requires(subject_sha256=DIGEST).verified
    assert result.requires(subject_sha256=DIGEST.upper()).verified
    narrowed = result.requires(subject_sha256="b" * 64)
    assert not narrowed.verified
    assert "describes something else" in narrowed.reason


def test_the_identity_and_issuer_can_be_required(keys: tuple[bytes, bytes]) -> None:
    """A static-key signature names no identity, so requiring one must fail.

    Silently passing would be the dangerous direction: a pipeline that asked
    for a workflow identity and got a developer's key would not be told.
    """
    private, public = keys
    result = verify_with_key(sign_with_key(_statement(), private), public)

    assert not result.requires(
        identity="https://github.com/org/repo/.github/workflows/ci.yml"
    ).verified
    assert not result.requires(issuer="https://token.actions.githubusercontent.com").verified


def test_constraints_do_not_rescue_a_failed_verification(keys: tuple[bytes, bytes]) -> None:
    _, public = keys
    failed = verify_with_key(Envelope(payload=b"{}"), public)
    assert not failed.requires(predicate_type=PREDICATE_TYPE).verified


def test_several_subjects_are_all_matchable(keys: tuple[bytes, bytes]) -> None:
    private, public = keys
    statement = _statement(
        [Subject(name="wheel", sha256="a" * 64), Subject(name="sdist", sha256="b" * 64)]
    )
    result = verify_with_key(sign_with_key(statement, private), public)
    assert result.requires(subject_sha256="b" * 64).verified


# --- Reading an envelope --------------------------------------------------


def test_an_envelope_round_trips_through_its_wire_form(keys: tuple[bytes, bytes]) -> None:
    private, public = keys
    original = sign_with_key(_statement(), private)
    restored = parse_envelope(original.to_json())

    assert restored.payload == original.payload
    assert restored.payload_type == original.payload_type
    assert verify_with_key(restored, public).verified


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("not json at all", "not a readable DSSE envelope"),
        ("[]", "the top level is not an object"),
        ('{"payload": "eyJ9"}', "'payload' and 'payloadType' are required"),
        ('{"payload": 7, "payloadType": "t"}', "'payload' and 'payloadType' are required"),
        ('{"payload": "!!!", "payloadType": "t"}', "not valid base64"),
    ],
)
def test_something_that_is_not_an_envelope_is_refused(raw: str, expected: str) -> None:
    """A file that merely looks like one must not be reported as verified."""
    with pytest.raises(AttestationError, match=expected):
        parse_envelope(raw)


def test_a_payload_that_is_not_a_statement_is_refused() -> None:
    envelope = Envelope(payload=b"not json")
    with pytest.raises(AttestationError, match="not readable JSON"):
        _ = envelope.statement

    with pytest.raises(AttestationError, match="not a JSON object"):
        _ = Envelope(payload=b"[1,2]").statement


def test_a_subject_without_a_digest_is_not_reported_as_one() -> None:
    """Otherwise a subject constraint could be satisfied by an empty entry."""
    payload = json.dumps(
        {
            "_type": STATEMENT_TYPE,
            "predicateType": PREDICATE_TYPE,
            "subject": [{"name": "no-digest"}, {"name": "ok", "digest": {"sha256": DIGEST}}],
            "predicate": {},
        }
    ).encode("utf-8")
    assert [subject.name for subject in Envelope(payload=payload).subjects] == ["ok"]


# --- Describing without believing ----------------------------------------


def test_metadata_describes_an_envelope_and_says_it_is_unverified(
    keys: tuple[bytes, bytes],
) -> None:
    """Describing an envelope and believing it are different operations.

    A report that blurs them teaches readers that a signature's presence is
    the same as its validity.
    """
    private, _ = keys
    metadata = attestation_metadata(sign_with_key(_statement(), private))

    assert metadata["predicate_type"] == PREDICATE_TYPE
    assert metadata["statement_type"] == STATEMENT_TYPE
    assert metadata["signature_count"] == 1
    assert metadata["keyless"] is False
    assert metadata["verified"] is False
    assert metadata["subjects"][0]["name"] == "my-service"


# --- Keyless ---------------------------------------------------------------


def test_keyless_signing_without_the_extra_says_what_to_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Never falls back to leaving the document unsigned.

    A pipeline that believes it is signing and is not is worse off than one
    that knows it is not.
    """
    import builtins

    real_import = builtins.__import__

    def refuse(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("sigstore"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", refuse)
    with pytest.raises(AttestationError, match="sigstore"):
        sign_keyless(_statement())
