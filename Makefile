# Task runner. Works in Git Bash on Windows and in any POSIX shell.
# Every target is a thin wrapper around uv so the commands stay copy-pasteable.

.DEFAULT_GOAL := help
.PHONY: help install lint fmt type test test-all cov check up down logs \
        migrate migration regen-snapshot seed-advisories api worker clean

UV ?= uv

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Create the virtualenv and install every workspace member
	$(UV) sync --all-packages

lint: ## Lint and check formatting
	$(UV) run ruff check .
	$(UV) run ruff format --check .

fmt: ## Format and apply safe lint fixes
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

type: ## Type-check (strict on the analysis core)
	$(UV) run mypy packages/core/src packages/cli/src apps/api/src apps/worker/src

test: ## Run unit tests (no Postgres needed)
	$(UV) run pytest -m "not integration and not network and not benchmark"

test-all: ## Run every test including integration (needs `make up`)
	$(UV) run pytest -m "not network and not benchmark"

cov: ## Unit tests with a coverage report
	$(UV) run pytest -m "not integration and not network and not benchmark" \
		--cov --cov-report=term-missing

check: lint type test ## What CI runs

up: ## Start Postgres, apply migrations, run the API and seed advisories
	docker compose -f infra/docker-compose.yml up -d --build
	@echo "API and web UI on http://localhost:8000"

down: ## Stop the local stack
	docker compose -f infra/docker-compose.yml down

logs: ## Tail the local stack
	docker compose -f infra/docker-compose.yml logs -f

migrate: ## Apply migrations to the local database
	$(UV) run alembic -c infra/alembic.ini upgrade head

migration: ## Create a migration: make migration m="add findings table"
	$(UV) run alembic -c infra/alembic.ini revision --autogenerate -m "$(m)"

regen-snapshot: ## Rebuild the frozen test advisory snapshot from tools/build_test_snapshot.py
	$(UV) run python tools/build_test_snapshot.py

seed-advisories: ## Load the frozen test advisory snapshot into the local database
	$(UV) run python -m sscp_worker.main seed-advisories testdata/advisories

api: ## Run the API and HTML UI with reload, outside Docker
	$(UV) run uvicorn sscp_api.main:app --reload --port 8000

worker: ## Show the worker's available jobs
	$(UV) run python -m sscp_worker.main --help

clean: ## Remove caches and build artefacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
