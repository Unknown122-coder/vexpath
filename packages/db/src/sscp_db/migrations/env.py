"""Alembic environment.

The database URL comes from the environment, never from the ini file, so that
the same migration command works locally, in CI and against production without
editing a checked-in file.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sscp_db.engine import create_sync_engine
from sscp_db.tables import metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = metadata


def _database_url() -> str:
    url = os.environ.get("SSCP_DATABASE_URL") or config.get_main_option("sqlalchemy.url")
    if not url:
        msg = "set SSCP_DATABASE_URL (see .env.example) before running migrations"
        raise RuntimeError(msg)
    return url


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it, for review before a deploy."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live database."""
    engine = create_sync_engine(_database_url())
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            poolclass=pool.NullPool,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
