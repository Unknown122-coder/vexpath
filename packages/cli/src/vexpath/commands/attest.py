"""The ``vexpath attest`` command group: sign a document, and check a signature.

A VEX document that says "this does not apply to us" is worth something only
if a consumer can establish who said it. These commands are the two halves of
that: producing a signature somebody else can check, and checking one.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Annotated

import typer

from vexpath.output import OutputFormat, emit, emit_json, fail, fail_config, note, warn
from vexpath_core import attest
from vexpath_core.vex import OPENVEX_PREDICATE_TYPE

app = typer.Typer(
    help="Sign documents so their conclusions can be attributed, and verify signatures.",
    no_args_is_help=True,
)

#: What each document type's predicate is called. A verifier matches on this,
#: so guessing wrongly produces an attestation nothing will accept.
PREDICATE_TYPES = {
    "vex": OPENVEX_PREDICATE_TYPE,
    "results": attest.RESULTS_PREDICATE_TYPE,
}


@app.command("keygen")
def keygen(
    private_out: Annotated[
        Path,
        typer.Option("--private", dir_okay=False, help="Where to write the private key."),
    ] = Path("vexpath-signing.key"),
    public_out: Annotated[
        Path,
        typer.Option("--public", dir_okay=False, help="Where to write the public key."),
    ] = Path("vexpath-signing.pub"),
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite an existing key."),
    ] = False,
) -> None:
    """Generate an ed25519 keypair for static signing.

    Prefer keyless signing in CI: it binds the signature to the workflow that
    produced it, and there is no long-lived secret to leak. A static key is
    the right tool for an air-gapped pipeline, and for verifying an
    attestation with nothing but this tool.
    """
    for path in (private_out, public_out):
        if path.exists() and not force:
            fail_config(
                f"{path} already exists. Overwriting a signing key invalidates every "
                f"signature made with it, so pass --force if that is what you want."
            )

    private_pem, public_pem = attest.generate_key()
    private_out.parent.mkdir(parents=True, exist_ok=True)
    private_out.write_bytes(private_pem)
    public_out.write_bytes(public_pem)
    # Best effort: on Windows this is a no-op, and the warning below covers it.
    with contextlib.suppress(OSError):
        private_out.chmod(0o600)

    note(f"private key {private_out}")
    note(f"public key  {public_out}")
    note(f"key id      {attest.key_id(public_pem)}")
    warn(
        "The private key is unencrypted. Keep it out of version control and out "
        "of anything that logs file contents."
    )


@app.command("sign")
def sign(
    document: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, help="The document to sign."),
    ],
    document_type: Annotated[
        str,
        typer.Option(
            "--type",
            help="What kind of document this is: 'vex' or 'results'.",
        ),
    ] = "vex",
    key: Annotated[
        Path | None,
        typer.Option(
            "--key",
            exists=True,
            dir_okay=False,
            help=(
                "Sign with this ed25519 private key. Without it, signing is "
                "keyless through Sigstore and needs an OIDC credential, which "
                "CI has and a laptop usually does not."
            ),
        ),
    ] = None,
    subject: Annotated[
        list[str] | None,
        typer.Option(
            "--subject",
            help=(
                "What the attestation is about, as name=sha256. Repeatable. "
                "Defaults to the document itself, which is the honest subject "
                "when nothing else is named."
            ),
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", dir_okay=False, help="Write here instead of stdout."),
    ] = None,
) -> None:
    """Wrap a document in a signed in-toto attestation.

    The result is a DSSE envelope holding an in-toto Statement v1, which is
    what `cosign verify-attestation` and the in-toto tooling read.

    A failure to sign is always reported and never produces an unsigned
    envelope. A pipeline that believes it is signing and is not is worse off
    than one that knows it is not.
    """
    predicate_type = PREDICATE_TYPES.get(document_type)
    if predicate_type is None:
        fail_config(f"--type {document_type!r} is not one of: {', '.join(sorted(PREDICATE_TYPES))}")

    raw = document.read_bytes()
    try:
        predicate = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"{document} is not readable JSON, so it cannot be attested: {exc}")

    try:
        subjects = _subjects(subject, document, raw)
        statement = attest.build_statement(predicate, predicate_type, subjects)
        envelope = (
            attest.sign_with_key(statement, key.read_bytes())
            if key is not None
            else attest.sign_keyless(statement)
        )
    except attest.AttestationError as exc:
        fail(str(exc))

    note(f"predicate   {predicate_type}")
    for entry in subjects:
        note(f"subject     {entry.name} sha256:{entry.sha256[:16]}...")
    note("signing     " + ("static key" if key is not None else "keyless (Sigstore)"))
    if key is not None:
        warn(
            "Signed with a static key, so a consumer learns only that whoever "
            "holds that key made the claim. Keyless signing in CI names the "
            "workflow instead."
        )

    rendered = envelope.to_json()
    if output is None:
        emit(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8", newline="\n")
    note(f"written to {output}")


def _subjects(
    raw_subjects: list[str] | None, document: Path, payload: bytes
) -> list[attest.Subject]:
    """Work out what the attestation is about.

    Defaults to the document itself. That is the honest subject when nothing
    else is named: it says "this exact document is what I signed", which is
    weaker than naming a built artefact but is true, and inventing a subject
    would not be.
    """
    if not raw_subjects:
        return [attest.subject_for_bytes(payload, document.name)]

    subjects: list[attest.Subject] = []
    for entry in raw_subjects:
        name, separator, digest = entry.partition("=")
        if not separator:
            fail_config(
                f"--subject {entry!r} is not name=sha256. A subject needs a digest "
                f"a verifier can match against the artefact in front of them."
            )
        try:
            subjects.append(attest.Subject(name=name.strip(), sha256=digest.strip()))
        except attest.AttestationError as exc:
            fail_config(str(exc))
    return subjects


@app.command("verify")
def verify(
    envelope_path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, help="The attestation to check."),
    ],
    key: Annotated[
        Path | None,
        typer.Option(
            "--key",
            exists=True,
            dir_okay=False,
            help="Public key to verify a static-key signature against.",
        ),
    ] = None,
    expect_type: Annotated[
        str | None,
        typer.Option(
            "--expect-type",
            help=(
                "Require this predicate type: 'vex', 'results', or a URI. An "
                "attestation about something else is not an answer to what you "
                "asked."
            ),
        ),
    ] = None,
    expect_subject: Annotated[
        str | None,
        typer.Option(
            "--expect-subject",
            help=(
                "Require that the attestation covers this sha256 digest. Without "
                "it, a valid signature over someone else's artefact passes."
            ),
        ),
    ] = None,
    expect_identity: Annotated[
        str | None,
        typer.Option(
            "--expect-identity",
            help="Require this signer identity, such as a workflow URL.",
        ),
    ] = None,
    expect_issuer: Annotated[
        str | None,
        typer.Option("--expect-issuer", help="Require this OIDC issuer."),
    ] = None,
    output: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Check an attestation, and that it says what you asked about.

    Exits 1 when verification fails. A signature that merely verifies is a
    weaker fact than it sounds: it may cover a different artefact, a different
    kind of claim, or come from a different signer. The ``--expect`` options
    are how that gap is closed, and the output says which of them were applied.
    """
    try:
        envelope = attest.parse_envelope(envelope_path.read_text(encoding="utf-8"))
    except attest.AttestationError as exc:
        fail(str(exc))

    if key is None:
        fail_config(
            "--key is required. Verifying a keyless signature means checking a "
            "certificate and a transparency-log entry against an identity, which "
            "is what 'cosign verify-attestation' does; this command verifies "
            "static-key signatures."
        )

    try:
        result = attest.verify_with_key(envelope, key.read_bytes())
    except attest.AttestationError as exc:
        fail(str(exc))

    wanted_type = PREDICATE_TYPES.get(expect_type or "", expect_type)
    result = result.requires(
        predicate_type=wanted_type,
        subject_sha256=expect_subject,
        identity=expect_identity,
        issuer=expect_issuer,
    )

    applied = [
        name
        for name, value in (
            ("predicate type", wanted_type),
            ("subject digest", expect_subject),
            ("identity", expect_identity),
            ("issuer", expect_issuer),
        )
        if value
    ]

    if output is OutputFormat.JSON:
        emit_json(
            {
                "verified": result.verified,
                "reason": result.reason,
                "method": result.method,
                "key_id": result.key_id,
                "identity": result.identity,
                "issuer": result.issuer,
                "predicate_type": result.predicate_type,
                "subjects": [entry.as_json() for entry in result.subjects],
                "constraints_applied": applied,
            }
        )
    else:
        lines = [result.summary_line()]
        lines.append("constraints     " + (", ".join(applied) if applied else "none applied"))
        if not applied and result.verified:
            lines.append("")
            lines.append(
                "A signature with no constraints applied says only that someone "
                "holding that key signed something. Pass --expect-type and "
                "--expect-subject to make it say more."
            )
        emit("\n".join(lines) + "\n")

    if not result.verified:
        raise typer.Exit(code=1)


@app.command("inspect")
def inspect(
    envelope_path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, help="The attestation to describe."),
    ],
) -> None:
    """Describe an attestation without verifying it.

    Deliberately a separate command. Describing an envelope and believing it
    are different operations, and a tool that blurs them teaches people that a
    signature's presence is the same as its validity.
    """
    try:
        envelope = attest.parse_envelope(envelope_path.read_text(encoding="utf-8"))
        metadata = attest.attestation_metadata(envelope)
    except attest.AttestationError as exc:
        fail(str(exc))

    emit_json(metadata)
    warn("Nothing here was verified. Use 'vexpath attest verify' for that.")


__all__ = ["PREDICATE_TYPES", "app"]
