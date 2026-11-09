# One image, two process types: the API and the worker (ADR-0011 folds the web
# UI into the API, so there is no third).
#
# Build from the repository root:
#   docker build -f infra/Dockerfile -t vexpath .

# --- Builder ---------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependency metadata first, so a source change does not invalidate the
# dependency layer.
COPY pyproject.toml uv.lock ./
COPY packages/core/pyproject.toml packages/core/
COPY packages/platform/pyproject.toml packages/platform/
COPY packages/db/pyproject.toml packages/db/
COPY packages/cli/pyproject.toml packages/cli/
COPY apps/api/pyproject.toml apps/api/
COPY apps/worker/pyproject.toml apps/worker/

# READMEs are referenced by the package metadata, so the build needs them.
COPY packages/core/README.md packages/core/
COPY packages/platform/README.md packages/platform/
COPY packages/db/README.md packages/db/
COPY packages/cli/README.md packages/cli/
COPY apps/api/README.md apps/api/
COPY apps/worker/README.md apps/worker/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --all-packages --no-install-workspace

COPY packages/ packages/
COPY apps/ apps/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --all-packages

# --- Runtime ---------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# git is needed by the patch-diff job (M2), which clones upstream repositories
# at a fix commit to extract vulnerable symbols.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git curl \
    && rm -rf /var/lib/apt/lists/*

# Analysis runs as an unprivileged user and never executes analysed code
# (docs/06-threat-model.md).
RUN useradd --create-home --uid 10001 vexpath

WORKDIR /app
COPY --from=builder --chown=vexpath:vexpath /app /app
COPY --chown=vexpath:vexpath infra/alembic.ini infra/alembic.ini
COPY --chown=vexpath:vexpath testdata/ testdata/

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER vexpath
EXPOSE 8000

# Liveness only: deliberately independent of the database, so a database
# outage does not make the orchestrator restart a healthy process.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
    CMD curl --fail --silent http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "vexpath_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
