"""Configuration behaviour."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vexpath_platform.settings import Environment, LogFormat, Settings


def test_defaults_are_local_development(clean_environment: None) -> None:
    settings = Settings()
    assert settings.env is Environment.LOCAL
    assert settings.log_format is LogFormat.CONSOLE
    assert settings.database_url.startswith("postgresql+psycopg://")


def test_production_refuses_the_placeholder_secret(clean_environment: None) -> None:
    """A deployment must not fall back to a known key."""
    with pytest.raises(ValidationError, match="must be set to a real secret"):
        Settings(env=Environment.PRODUCTION, base_url="https://vexpath.dev")

    accepted = Settings(
        env=Environment.PRODUCTION,
        secret_key="a-real-secret-value",
        # Production also refuses a plain-HTTP base URL, because the session
        # cookie is Secure there and a browser would never send it back: the
        # deployment would serve every page and sign nobody in.
        base_url="https://vexpath.dev",
    )
    assert accepted.env.is_production


def test_interactive_api_docs_are_closed_in_production(clean_environment: None) -> None:
    assert Settings(env=Environment.LOCAL).docs_url == "/docs"
    assert (
        Settings(
            env=Environment.PRODUCTION, secret_key="x" * 32, base_url="https://vexpath.dev"
        ).docs_url
        is None
    )


def test_settings_come_from_prefixed_environment_variables(
    clean_environment: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VEXPATH_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("VEXPATH_S3_BUCKET", "other-bucket")
    settings = Settings()
    assert settings.log_level == "DEBUG"
    assert settings.s3_bucket == "other-bucket"


def test_unknown_variables_are_ignored(
    clean_environment: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The process environment is full of unrelated variables; one of them must
    # not stop the application from starting.
    monkeypatch.setenv("VEXPATH_SOMETHING_WE_REMOVED", "1")
    assert Settings().env is Environment.LOCAL


# --- Configuration that does nothing --------------------------------------

#: Settings whose **field** nothing reads.
#:
#: Not the same as "the environment variable does nothing", and the
#: difference caught me out: two of these name variables the command line
#: reads directly from ``os.environ`` with its own constants, so the variable
#: is live while the field beside it is dead. Only ``github_token`` and the
#: ``s3_*`` group are inert end to end -- zero references anywhere in the
#: source.
#:
#: Asking an operator for a credential that does nothing is worse than not
#: asking: they create it, store it, and believe it is load-bearing. The
#: deployment runbook said a GitHub token "raises the API rate limit for the
#: advisory pipeline's patch diffing" -- it does not, because that job runs
#: the ``git`` binary and never calls the API -- and a token was created on
#: the strength of that sentence.
#:
#: So the list is asserted in both directions: nothing here may have a
#: reader, and nothing outside it may lack one. Wiring one of these up fails
#: this test, which is the reminder to fix the documentation at the same time.
DECLARED_BUT_UNREAD = frozenset(
    {
        # The *field* is dead; the environment variable is not. The command
        # line reads VEXPATH_ADVISORY_SNAPSHOT_DIR straight from os.environ
        # with its own constant (vexpath/sources.py), so the variable works
        # and this Settings field is a second name for it that nothing
        # consults. Server-side there is no reader at all, which is why the
        # entry in infra/fly.toml does nothing.
        "advisory_snapshot_dir",
        "github_token",
        # Same shape: VEXPATH_OSV_API_BASE is read by the command line
        # (vexpath/sources.py) and pointing the scanner at a mirror does
        # work. What nothing reads is this field, so a server-side component
        # asking Settings for it would always get the default.
        "osv_api_base",
        "s3_access_key_id",
        "s3_bucket",
        "s3_endpoint_url",
        "s3_region",
        "s3_secret_access_key",
    }
)

#: Where a setting may be mentioned without counting as a reader: its own
#: definition. The scrubbing lists in logging.py and tracing.py name fields as
#: strings rather than attributes, so the pattern below does not see them --
#: and those two modules are real consumers of the logging and Sentry
#: settings, so excluding the files would hide the readers along with the
#: mentions.
_NOT_READERS = ("settings.py",)


def _readers(field: str) -> list[str]:
    """Files that read ``field`` off a settings object."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    pattern = re.compile(rf"\.{re.escape(field)}\b")
    found: list[str] = []
    for directory in ("packages", "apps", "tools", "infra"):
        for path in (root / directory).rglob("*.py"):
            if path.name.endswith(_NOT_READERS) or "test" in path.parts:
                continue
            if path.name.startswith("test_") or path.name == "conftest.py":
                continue
            if pattern.search(path.read_text(encoding="utf-8")):
                found.append(str(path.relative_to(root)))
    return found


def test_nothing_reads_the_settings_documented_as_unread() -> None:
    for field in sorted(DECLARED_BUT_UNREAD):
        readers = _readers(field)
        assert not readers, (
            f"{field} is listed as unread but {readers} reads it. Wire-up is "
            "good news -- remove it from DECLARED_BUT_UNREAD and correct "
            "docs/09-deployment.md, which tells operators it does nothing."
        )


def test_every_other_setting_is_actually_used() -> None:
    from vexpath_platform.settings import Settings

    unused: list[str] = []
    for field in sorted(Settings.model_fields):
        if field in DECLARED_BUT_UNREAD:
            continue
        if not _readers(field):
            unused.append(field)

    assert not unused, (
        f"{unused} is configuration nothing consumes. Either use it, delete "
        "it, or add it to DECLARED_BUT_UNREAD and say so in the runbook -- "
        "but do not leave an operator believing it matters."
    )
