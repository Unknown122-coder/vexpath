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
from typing import Any

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


# --- The release workflow -------------------------------------------------

#: The packages that go to PyPI, and the environment each publishes from.
#: Separate environments are forced rather than chosen: a PyPI *pending*
#: publisher is keyed on owner, repository, workflow filename **and**
#: environment, so two packages claiming unclaimed names from one identical
#: configuration is refused.
PUBLISHED = {"vexpath-core": "pypi-core", "vexpath": "pypi"}


@pytest.fixture(scope="module")
def release() -> dict[str, Any]:
    import yaml

    document: dict[str, Any] = yaml.safe_load(
        (INFRA.parent / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    return document


def test_each_published_package_has_its_own_environment(release: dict[str, Any]) -> None:
    jobs = release["jobs"]
    environments = {
        job["environment"]["name"] for name, job in jobs.items() if name.startswith("publish-")
    }
    assert environments == set(PUBLISHED.values()), environments


def test_the_core_publishes_before_the_command_line(release: dict[str, Any]) -> None:
    # `vexpath` pins `vexpath-core` at an exact version, so an installer that
    # found one without the other would resolve nothing.
    assert "publish-core" in release["jobs"]["publish-cli"]["needs"]


def test_each_publish_job_selects_only_its_own_files(release: dict[str, Any]) -> None:
    """The glob must not catch a sibling.

    `vexpath-<version>*` and `vexpath_core-<version>*` are mutually exclusive
    because of the hyphen -- a prefix of just `vexpath` would also match
    `vexpath_api`, and publishing the API package to the `vexpath` project
    would be both wrong and irreversible.
    """
    scripts = {
        name: "\n".join(step.get("run", "") for step in job["steps"])
        for name, job in release["jobs"].items()
        if name.startswith("publish-")
    }
    assert "dist/vexpath_core-${{ needs.build.outputs.version }}*" in scripts["publish-core"]
    assert "dist/vexpath-${{ needs.build.outputs.version }}*" in scripts["publish-cli"]
    # Proven against real filenames in tools/verify_dist.py's output; asserted
    # here so a change to the pattern is noticed.
    for name, script in scripts.items():
        assert "packages-dir: dist" not in script, name


def test_nothing_publishes_a_package_we_do_not_intend_to(release: dict[str, Any]) -> None:
    text = (INFRA.parent / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    # The four unpublished packages ship in the container image instead.
    # Publishing one by accident cannot be undone.
    for unpublished in ("vexpath_api-", "vexpath_db-", "vexpath_platform-", "vexpath_worker-"):
        assert unpublished not in text, unpublished


def test_a_release_refuses_a_tag_that_disagrees_with_the_version(
    release: dict[str, Any],
) -> None:
    script = "\n".join(step.get("run", "") for step in release["jobs"]["build"]["steps"])
    # A release nobody can find by version is worse than no release.
    assert "does not match version" in script


def test_a_release_proves_the_wheel_installs_before_publishing(
    release: dict[str, Any],
) -> None:
    script = "\n".join(step.get("run", "") for step in release["jobs"]["build"]["steps"])
    # The whole suite runs inside the workspace, so only this catches a
    # package that imports something it does not declare.
    assert "tools/verify_dist.py" in script


def test_publishing_fails_on_a_version_that_already_exists(release: dict[str, Any]) -> None:
    text = (INFRA.parent / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    # Silently skipping would look like a successful release of something
    # that was never uploaded.
    assert "skip-existing: false" in text
    assert "skip-existing: true" not in text


def test_no_publish_job_holds_a_token(release: dict[str, Any]) -> None:
    for name, job in release["jobs"].items():
        if not name.startswith("publish-"):
            continue
        # Trusted Publishing: the job authenticates with its own OIDC
        # identity. A long-lived token in a repository whose subject is
        # supply-chain security would be hard to defend.
        assert job["permissions"]["id-token"] == "write"
        assert "secrets." not in str(job)


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
