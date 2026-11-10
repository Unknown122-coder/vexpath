"""Configuration, read from the environment.

Every setting has an ``VEXPATH_`` prefix and a documented entry in
``.env.example``. Secrets have no defaults outside local development: a missing
secret must fail at start-up, not silently fall back to something insecure.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Which deployment this process is."""

    LOCAL = "local"
    STAGING = "staging"
    PRODUCTION = "production"
    TEST = "test"

    @property
    def is_production(self) -> bool:
        return self is Environment.PRODUCTION


class LogFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"


#: Sentinel, not a credential: its only purpose is to be recognised and
#: rejected when an environment that matters is started with it.
_LOCAL_SECRET = "change-me-in-every-environment"  # noqa: S105


class Settings(BaseSettings):
    """Process configuration."""

    model_config = SettingsConfigDict(
        env_prefix="VEXPATH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Environment = Environment.LOCAL
    base_url: str = "http://localhost:8000"
    secret_key: str = _LOCAL_SECRET
    log_level: str = "INFO"
    log_format: LogFormat = LogFormat.CONSOLE

    # --- Database ----------------------------------------------------------
    database_url: str = "postgresql+psycopg://vexpath:vexpath@localhost:5432/vexpath"
    database_echo: bool = False

    # --- Object storage ----------------------------------------------------
    s3_endpoint_url: str | None = None
    s3_bucket: str = "vexpath-artifacts"
    s3_access_key_id: str | None = None
    s3_secret_access_key: str | None = None
    s3_region: str = "auto"

    # --- Advisory data -----------------------------------------------------
    #: When set, advisories are read from this local snapshot instead of the
    #: OSV API, which makes scans reproducible and lets tests run offline.
    advisory_snapshot_dir: Path | None = None
    osv_api_base: str = "https://api.osv.dev"
    github_token: str | None = None

    # --- Sign-in -----------------------------------------------------------
    #: GitHub is the only identity provider at launch. Absent, the sign-in
    #: page says so rather than redirecting to a broken authorisation URL:
    #: a deployment missing its credentials should be obvious on the page
    #: that needs them, not a 500 from GitHub.
    github_client_id: str | None = None
    github_client_secret: str | None = None
    #: Overridable so a test can point the whole flow at a local stand-in
    #: without monkeypatching a URL constant.
    github_oauth_base: str = "https://github.com"
    github_api_base: str = "https://api.github.com"

    @property
    def sign_in_available(self) -> bool:
        """Whether this deployment can sign anybody in.

        Both halves or neither: a client id with no secret produces an
        authorisation redirect that fails at the exchange, which is the most
        confusing possible way to be misconfigured.
        """
        return bool(self.github_client_id and self.github_client_secret)

    @property
    def cookies_require_https(self) -> bool:
        """Whether the session cookie carries ``Secure``.

        On everywhere there is HTTPS to use, which is everywhere but local
        development. Expressed as a property so no handler has to work out
        the rule, and so getting it wrong is one change rather than several.
        """
        return self.env is not Environment.LOCAL and self.env is not Environment.TEST

    @model_validator(mode="after")
    def _reject_insecure_production(self) -> Settings:
        if self.env.is_production and self.secret_key == _LOCAL_SECRET:
            msg = "VEXPATH_SECRET_KEY must be set to a real secret in production"
            raise ValueError(msg)
        return self

    @property
    def docs_url(self) -> str | None:
        """Interactive API docs, exposed everywhere except production."""
        return None if self.env.is_production else "/docs"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, read once.

    Cached so that configuration cannot change under a running request. Tests
    clear the cache when they need a different environment.
    """
    return Settings()


__all__ = ["Environment", "LogFormat", "Settings", "get_settings"]
