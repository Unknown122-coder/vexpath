"""The deployment artefacts, checked for the things that break a deploy.

Not a substitute for deploying, which needs an account nobody's test suite
should have. What these catch is the class of mistake that is only visible
after a deploy: a release command that would not run migrations, a health
check pointed at the wrong probe, a secret committed into a file, and a
production configuration that starts happily and then cannot sign anybody in.

The last one is the reason this file exists. A production deployment with an
``http://`` base URL serves every page, passes every health check, and signs
nobody in — the session cookie carries ``Secure`` so a browser never sends it
back, and the sign-in redirect lands on the sign-in page with nothing in any
log to explain it.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from vexpath_platform.settings import Environment, Settings

INFRA = Path(__file__).resolve().parents[1]
FLY = INFRA / "fly.toml"
DOCKERFILE = INFRA / "Dockerfile"
COMPOSE = INFRA / "docker-compose.yml"

#: What a secret looks like if somebody pastes one in. Not exhaustive, and not
#: trying to be: it is the shapes this system itself issues plus the obvious
#: provider prefixes.
SECRET_SHAPES = (
    "vexpath_live_",
    "whsec_",
    "ghp_",
    "github_pat_",
    "gho_",
    "-----BEGIN",
    "postgres://",
    "postgresql://",
)


@pytest.fixture(scope="module")
def fly() -> dict[str, object]:
    return tomllib.loads(FLY.read_text(encoding="utf-8"))


# --- The production configuration refuses to be wrong ----------------------


def test_production_refuses_the_placeholder_secret() -> None:
    with pytest.raises(ValueError, match="VEXPATH_SECRET_KEY"):
        Settings(env=Environment.PRODUCTION, base_url="https://vexpath.dev")


def test_production_refuses_a_plain_http_base_url() -> None:
    # The whole reason this check exists: every page works, every health
    # check passes, and sign-in silently never completes.
    with pytest.raises(ValueError, match="https"):
        Settings(
            env=Environment.PRODUCTION,
            secret_key="a-real-secret",
            base_url="http://vexpath.dev",
        )


def test_a_correct_production_configuration_is_accepted() -> None:
    settings = Settings(
        env=Environment.PRODUCTION, secret_key="a-real-secret", base_url="https://vexpath.dev"
    )
    assert settings.cookies_require_https is True
    # The interactive docs are off in production: a schema browser is a
    # convenience for a developer and an index for anybody else.
    assert settings.docs_url is None


def test_local_development_is_not_held_to_the_same_rule() -> None:
    # A developer has no HTTPS to use, so the cookie is not Secure there and
    # an http base URL is correct rather than broken.
    settings = Settings(env=Environment.LOCAL, base_url="http://localhost:8000")
    assert settings.cookies_require_https is False


# --- fly.toml --------------------------------------------------------------


def test_the_deploy_runs_migrations_before_serving(fly: dict[str, object]) -> None:
    deploy = fly["deploy"]
    assert isinstance(deploy, dict)
    # Code that expects a column must not serve a request before that column
    # exists, and a failed release command stops the deploy.
    assert "alembic" in deploy["release_command"]
    assert "upgrade head" in deploy["release_command"]


def test_traffic_is_gated_on_readiness_and_restarts_on_liveness(
    fly: dict[str, object],
) -> None:
    service = fly["http_service"]
    assert isinstance(service, dict)
    checks = (
        service["http_service.checks"] if "http_service.checks" in service else service["checks"]
    )
    assert isinstance(checks, list)
    # /readyz decides whether a machine receives traffic, so a database
    # outage stops requests without restarting anything.
    assert any(check["path"] == "/readyz" for check in checks)

    top_level = fly["checks"]
    assert isinstance(top_level, dict)
    # /healthz decides whether a machine is restarted, and is deliberately
    # independent of the database: otherwise one outage restarts every
    # machine at once.
    assert any(check["path"] == "/healthz" for check in top_level.values())


def test_the_deployment_declares_production(fly: dict[str, object]) -> None:
    env = fly["env"]
    assert isinstance(env, dict)
    assert env["VEXPATH_ENV"] == "production"
    assert env["VEXPATH_BASE_URL"].startswith("https://")
    assert env["VEXPATH_LOG_FORMAT"] == "json"
    # Fly terminates TLS and sets the header, so believing it is correct here
    # and nowhere else.
    assert env["VEXPATH_TRUST_PROXY_HEADERS"] == "true"
    assert env["VEXPATH_RATE_LIMIT_ENABLED"] == "true"


def test_only_one_machine_runs_until_the_limiter_is_shared(
    fly: dict[str, object],
) -> None:
    service = fly["http_service"]
    assert isinstance(service, dict)
    # The rate limiter keeps its counters in the process, so a second machine
    # allows the configured rate again. Scaling past one means moving them to
    # Postgres first, and this assertion is where somebody finds that out.
    assert service["min_machines_running"] == 1


def test_no_deployment_file_carries_a_secret() -> None:
    for path in (FLY, DOCKERFILE, COMPOSE):
        text = path.read_text(encoding="utf-8")
        for shape in SECRET_SHAPES:
            if shape in ("postgres://", "postgresql://") and path is COMPOSE:
                # The compose file holds the local development URL, whose
                # password is the word "vexpath" and is meant to be known.
                continue
            assert shape not in text, f"{path.name} looks like it holds a secret: {shape}"


# --- The image's entry point ----------------------------------------------


def test_the_image_passes_the_event_loop_factory() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    # Without it uvicorn builds its own loop, and on Windows picks one psycopg
    # cannot use: the process looks healthy and every database query fails.
    assert "vexpath_platform.eventloop:event_loop_factory" in text


def test_the_image_does_not_log_the_request_path_twice() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    # uvicorn's access log is a second, unstructured copy of an event the
    # application already logs -- carrying the literal path, which is tenant
    # data this project keeps out of the logs.
    assert "--no-access-log" in text


def test_the_image_runs_as_an_unprivileged_user() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    # The analysis never executes what it reads, but a defence that costs one
    # line is worth having anyway.
    assert "USER vexpath" in text
    assert "useradd" in text


def test_the_container_health_check_does_not_depend_on_the_database() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    healthcheck = text[text.index("HEALTHCHECK") :]
    # A database outage must not make the orchestrator restart a process that
    # is working fine.
    assert "/healthz" in healthcheck
    assert "/readyz" not in healthcheck
