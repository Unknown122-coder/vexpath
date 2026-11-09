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
        Settings(env=Environment.PRODUCTION)

    accepted = Settings(env=Environment.PRODUCTION, secret_key="a-real-secret-value")
    assert accepted.env.is_production


def test_interactive_api_docs_are_closed_in_production(clean_environment: None) -> None:
    assert Settings(env=Environment.LOCAL).docs_url == "/docs"
    assert Settings(env=Environment.PRODUCTION, secret_key="x" * 32).docs_url is None


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
