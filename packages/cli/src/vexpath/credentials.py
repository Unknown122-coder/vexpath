"""Where the command-line tool keeps an API key, and how it finds one.

A key is a bearer credential: whoever holds it is the organisation. So the two
decisions here are about not leaking it and not surprising anyone about which
one is in use.

**The environment wins over the stored file.** CI sets ``VEXPATH_API_KEY`` from
a secret, and a stored file on a shared build machine must not silently
override it. A developer who has logged in locally and then exports a key for a
one-off command gets the exported one, which is what they asked for.

**The file is written with no permissions for anybody else**, and the tool says
where it is. A credential whose location is a mystery is one nobody rotates.

**Nothing prints the key.** Not in a confirmation, not in a log line, not in an
error. The visible prefix is enough to say which key is in use, and is what
gets shown instead.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from vexpath_core.keyformat import KEY_PREFIX, display_prefix, looks_like_key

#: Read before the stored file. CI sets this from a secret, and a stored file
#: must not override it.
KEY_ENVIRONMENT_VARIABLE = "VEXPATH_API_KEY"

#: Where the platform lives, overridable for a self-hosted install.
URL_ENVIRONMENT_VARIABLE = "VEXPATH_API_URL"

#: The deployment this tool talks to when nothing says otherwise.
#:
#: It was ``https://api.vexpath.dev`` until 2026-11-12, which is a hostname
#: nobody owns: ``vexpath login`` stored it silently and the first upload
#: failed with a DNS error naming a domain the user had never heard of. A
#: default that points nowhere is worse than no default, because it fails
#: later and somewhere else.
DEFAULT_API_URL = "https://vexpath.fly.dev"

#: Overrides the whole configuration directory, which is what a test needs and
#: what a container with a read-only home directory needs too.
HOME_ENVIRONMENT_VARIABLE = "VEXPATH_CONFIG_DIR"


class CredentialError(Exception):
    """Raised when a credential cannot be stored or read."""


@dataclass(frozen=True, slots=True)
class Credential:
    """A key and where it came from.

    The source is carried because "which key am I using" is the question
    behind most authentication confusion, and the answer is usually that one
    place overrode another.
    """

    secret: str
    api_url: str
    #: ``environment`` or ``file``.
    source: str

    @property
    def prefix(self) -> str:
        """What is safe to print."""
        return display_prefix(self.secret)

    def __repr__(self) -> str:
        """Never render the secret.

        A credential that appears in a traceback has leaked, and tracebacks
        are produced exactly when attention is elsewhere.
        """
        return f"Credential(prefix={self.prefix!r}, source={self.source!r})"


def config_directory() -> Path:
    """Where the credential file lives.

    Follows the platform convention, and respects an override so a container
    with a read-only home directory, or a test, can point it elsewhere.
    """
    override = os.environ.get(HOME_ENVIRONMENT_VARIABLE)
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "vexpath"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "vexpath"


def credential_path() -> Path:
    return config_directory() / "credentials.json"


def load() -> Credential | None:
    """The credential to use, or None when there is none.

    The environment is checked first and deliberately: a stored file on a
    shared build machine must not override a key CI supplied from a secret.
    """
    from_environment = os.environ.get(KEY_ENVIRONMENT_VARIABLE, "").strip()
    if from_environment:
        return Credential(secret=from_environment, api_url=_api_url(None), source="environment")

    path = credential_path()
    if not path.is_file():
        return None
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        msg = (
            f"{path} is not readable as a credential file: {exc}. Delete it and "
            f"run 'vexpath login' again."
        )
        raise CredentialError(msg) from exc

    secret = str(stored.get("api_key") or "").strip()
    if not secret:
        return None
    return Credential(secret=secret, api_url=_api_url(stored.get("api_url")), source="file")


def _api_url(stored: object) -> str:
    """Which platform to talk to.

    The environment wins here too, so a one-off command against a staging
    deployment does not require editing a file and remembering to change it
    back.
    """
    from_environment = os.environ.get(URL_ENVIRONMENT_VARIABLE, "").strip()
    if from_environment:
        return from_environment.rstrip("/")
    if isinstance(stored, str) and stored.strip():
        return stored.strip().rstrip("/")
    return DEFAULT_API_URL


def store(secret: str, api_url: str) -> Path:
    """Write a credential, readable only by its owner.

    Raises:
        CredentialError: if the key is not shaped like one, or the file cannot
            be written. Storing something that is not a key would turn a
            typo into an authentication failure on the next command, with
            nothing to connect the two.
    """
    candidate = secret.strip()
    if not looks_like_key(candidate):
        msg = (
            f"that does not look like an API key: one starts with "
            f"{KEY_PREFIX!r} and is created in the dashboard"
        )
        raise CredentialError(msg)

    directory = config_directory()
    path = credential_path()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        # Written through a temporary file with restrictive permissions set
        # before any content, so the secret is never briefly world-readable.
        temporary = path.with_suffix(".partial")
        temporary.write_text(
            json.dumps({"api_key": candidate, "api_url": api_url.rstrip("/")}, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
        temporary.replace(path)
    except OSError as exc:
        msg = f"the credential could not be written to {path}: {exc}"
        raise CredentialError(msg) from exc

    return path


def display_prefix_of(secret: str) -> str:
    """What is safe to print for a key not yet stored.

    Exists so no caller is tempted to slice the secret itself and get the
    boundary wrong.
    """
    return display_prefix(secret)


def forget() -> bool:
    """Remove a stored credential.

    Returns True when there was one. Does not touch the environment variable,
    and the caller says so: a user who logs out and still has a key exported
    is still authenticated, and finding that out later is worse than being
    told now.
    """
    path = credential_path()
    if not path.is_file():
        return False
    path.unlink()
    return True


__all__ = [
    "DEFAULT_API_URL",
    "HOME_ENVIRONMENT_VARIABLE",
    "KEY_ENVIRONMENT_VARIABLE",
    "URL_ENVIRONMENT_VARIABLE",
    "Credential",
    "CredentialError",
    "config_directory",
    "credential_path",
    "display_prefix_of",
    "forget",
    "load",
    "store",
]
