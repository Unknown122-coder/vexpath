"""``vexpath login``, ``whoami`` and ``logout``.

Three commands whose whole job is to make it obvious which credential is in
use. Most authentication confusion is not "my key is wrong", it is "which key
is this using", and the answer is usually that one source overrode another.
So every one of these says where the credential came from.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any

import httpx
import typer

from vexpath import credentials
from vexpath.output import OutputFormat, emit, emit_json, fail, fail_config, note, warn

app = typer.Typer(help="Store and check the credential used for uploads.", no_args_is_help=True)

_TIMEOUT = 30.0


@app.command("login")
def login(
    key: Annotated[
        str | None,
        typer.Option(
            "--key",
            help=(
                "The API key. Omitted, it is read from the terminal without "
                "echoing, so it does not land in shell history."
            ),
        ),
    ] = None,
    api_url: Annotated[
        str | None,
        typer.Option("--api-url", help="Platform to talk to, for a self-hosted install."),
    ] = None,
) -> None:
    """Verify an API key and store it.

    The key is checked against the platform before it is written. Storing an
    unverified credential turns a typo into an authentication failure on some
    later command, with nothing to connect the two.
    """
    secret = key or typer.prompt("API key", hide_input=True)
    url = (api_url or credentials.DEFAULT_API_URL).rstrip("/")

    identity = _whoami(url, secret)
    try:
        path = credentials.store(secret, url)
    except credentials.CredentialError as exc:
        fail_config(str(exc))

    note(f"signed in to {identity['org_name']} ({identity['org_slug']})")
    note(f"key {credentials.display_prefix_of(secret)}")
    note(f"stored in {path}")
    if credentials.KEY_ENVIRONMENT_VARIABLE in _environment():
        # Said now rather than discovered later: the environment wins, so the
        # key just stored will not be the one used.
        warn(
            f"${credentials.KEY_ENVIRONMENT_VARIABLE} is set, and it takes "
            f"precedence over the stored credential. Unset it to use this one."
        )


@app.command("whoami")
def whoami(
    output: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Show which credential is in use, and for which organisation.

    Exits 3 when there is none, so a CI step can check for a credential
    before running a scan it intends to upload.
    """
    credential = _credential()
    identity = _whoami(credential.api_url, credential.secret)

    if output is OutputFormat.JSON:
        emit_json({**identity, "source": credential.source, "api_url": credential.api_url})
        return

    emit(
        "\n".join(
            [
                f"{'organisation':<16}{identity['org_name']} ({identity['org_slug']})",
                f"{'projects':<16}{identity['project_count']}",
                f"{'credential':<16}{credential.prefix}",
                # Which source won. This is the question behind most
                # authentication confusion.
                f"{'from':<16}{_source_label(credential.source)}",
                f"{'platform':<16}{credential.api_url}",
            ]
        )
        + "\n"
    )


def _source_label(source: str) -> str:
    if source == "environment":
        return f"${credentials.KEY_ENVIRONMENT_VARIABLE}"
    return str(credentials.credential_path())


@app.command("logout")
def logout() -> None:
    """Remove the stored credential.

    Says plainly when an exported key means you are still authenticated.
    Finding that out later is worse than being told now.
    """
    removed = credentials.forget()
    if removed:
        note(f"removed {credentials.credential_path()}")
    else:
        note("there was no stored credential")

    if credentials.KEY_ENVIRONMENT_VARIABLE in _environment():
        warn(
            f"${credentials.KEY_ENVIRONMENT_VARIABLE} is still set, so uploads "
            f"will continue to work. Unset it to sign out completely."
        )


def credential_or_exit() -> credentials.Credential:
    """The credential to use, or an explanation and exit 3.

    Public because the scan command needs it before it starts work: finding
    out there is no credential after a four-minute analysis wastes the
    analysis.
    """
    return _credential()


def _credential() -> credentials.Credential:
    try:
        credential = credentials.load()
    except credentials.CredentialError as exc:
        fail_config(str(exc))
    if credential is None:
        fail_config(
            f"no credential. Run 'vexpath login', or set "
            f"${credentials.KEY_ENVIRONMENT_VARIABLE} in CI."
        )
    return credential


def _whoami(api_url: str, secret: str) -> dict[str, Any]:
    """Ask the platform who this credential belongs to.

    Exits rather than returning an error, because every caller here needs the
    answer to continue, and each failure has a different remedy worth naming.
    """
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            response = client.get(f"{api_url}/v1/me", headers={"Authorization": f"Bearer {secret}"})
    except httpx.HTTPError as exc:
        fail(f"{api_url} could not be reached: {exc}")

    if response.status_code == 401:
        fail_config(
            "the platform rejected that key. Check it was copied whole, and "
            "that it has not been revoked in the dashboard."
        )
    if response.status_code == 404:
        fail_config(
            f"{api_url} does not look like a vexpath platform: /v1/me is not "
            f"there. Check --api-url."
        )
    if response.status_code >= 400:
        fail(f"{api_url} answered {response.status_code}: {response.text[:200]}")

    try:
        payload: dict[str, Any] = response.json()
    except ValueError:
        fail(f"{api_url} answered with something that is not JSON")
    return payload


def _environment() -> dict[str, str]:
    import os

    return dict(os.environ)


def fetch_policy(credential: credentials.Credential, project: str) -> str:
    """Read the expression a project is governed by.

    So that a policy set once in the dashboard governs every build, instead
    of every build having to be told the rule on its command line. The
    expression is returned rather than the preset name: the answer must not
    depend on the client's idea of what a preset means.
    """
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            response = client.get(
                f"{credential.api_url}/v1/projects/{project}/policy",
                headers={"Authorization": f"Bearer {credential.secret}"},
            )
    except httpx.HTTPError as exc:
        fail(f"{credential.api_url} could not be reached for the project policy: {exc}")

    if response.status_code == 401:
        fail_config("the platform rejected the credential. Run 'vexpath login' again.")
    if response.status_code == 404:
        fail_config(
            f"no policy for project {project!r}. Either the project does not exist "
            f"in this organisation, or it has no policy yet -- set one in the "
            f"dashboard, or drop --policy project to use the default."
        )
    if response.status_code >= 400:
        fail(f"the project policy could not be read: {response.status_code}")

    try:
        expression = str(response.json()["expression"])
    except (ValueError, KeyError, TypeError):
        fail("the platform returned a policy this build cannot read")

    if not expression.strip():
        fail_config(f"project {project!r} has an empty policy, which gates nothing")
    return expression


def upload_results(
    credential: credentials.Credential, project: str, results: Mapping[str, Any]
) -> dict[str, Any]:
    """Post a results document, and say what happened.

    Lives here rather than in the scan command so that the credential handling
    and the error messages are in one place: a failed upload after a
    successful scan is the moment a user most needs to be told which of the
    two went wrong. Every message below therefore begins by saying the scan
    itself completed, because the exit code cannot say it and a CI log read in
    a hurry will otherwise be understood as "the scan failed".
    """
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            response = client.post(
                f"{credential.api_url}/v1/scans",
                json={"project": project, "results": dict(results)},
                headers={"Authorization": f"Bearer {credential.secret}"},
            )
    except httpx.HTTPError as exc:
        fail(
            f"the scan completed but could not be uploaded: {credential.api_url} "
            f"could not be reached: {exc}"
        )

    if response.status_code == 401:
        fail_config("the scan completed but the platform rejected the credential.")
    if response.status_code == 404:
        fail_config(
            f"the scan completed but there is no project {project!r} in this "
            f"organisation. Create it in the dashboard, or check --project."
        )
    if response.status_code >= 400:
        fail(
            f"the scan completed but the upload was refused with "
            f"{response.status_code}: {response.text[:300]}"
        )

    try:
        stored: dict[str, Any] = response.json()
    except ValueError:
        fail(f"the scan was accepted but {credential.api_url} answered with non-JSON")
    return stored


__all__ = ["app", "credential_or_exit", "login", "logout", "upload_results", "whoami"]
