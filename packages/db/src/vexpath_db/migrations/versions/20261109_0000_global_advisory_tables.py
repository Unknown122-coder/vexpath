"""Baseline: global advisory corpus and call-graph cache index.

Creates the tables the advisory pipeline fills. These are global and read-only
to tenants, so no row-level security applies to them. Tenant tables arrive in a
later migration together with their policies.

Revision ID: 0001_global_advisory
Revises:
Created: 2026-11-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_global_advisory"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TEXT_ARRAY = postgresql.ARRAY(sa.Text())


def upgrade() -> None:
    op.create_table(
        "advisories",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("aliases", _TEXT_ARRAY, nullable=False),
        sa.Column("summary", sa.Text(), server_default="", nullable=False),
        sa.Column("details", sa.Text(), server_default="", nullable=False),
        sa.Column("severity", sa.String(length=16), server_default="UNKNOWN", nullable=False),
        sa.Column("cvss_v3", postgresql.JSONB(), nullable=True),
        sa.Column("cvss_v4", postgresql.JSONB(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("kev_added_at", sa.Date(), nullable=True),
        sa.Column("cwe_ids", _TEXT_ARRAY, nullable=False),
        sa.Column("references", postgresql.JSONB(), nullable=False),
        sa.Column("repo_url", sa.Text(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "symbols_status", sa.String(length=32), server_default="pending", nullable=False
        ),
        sa.Column("source_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "synced_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "symbols_status IN ('pending', 'extracted', 'derived_from_tags', 'none', 'failed')",
            name="ck_advisories_symbols_status",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_advisories"),
    )
    op.create_index(
        "ix_advisories_kev", "advisories", ["kev"], unique=False, postgresql_where=sa.text("kev")
    )
    op.create_index("ix_advisories_symbols_status", "advisories", ["symbols_status"])
    op.create_index("ix_advisories_modified_at", "advisories", ["modified_at"])

    op.create_table(
        "advisory_affected",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("advisory_id", sa.String(length=64), nullable=False),
        sa.Column("ecosystem", sa.String(length=64), nullable=False),
        sa.Column("package_name", sa.Text(), nullable=False),
        sa.Column("purl_base", sa.Text(), nullable=False),
        sa.Column("ranges", postgresql.JSONB(), nullable=False),
        sa.Column("versions", _TEXT_ARRAY, nullable=False),
        sa.Column("fixed_versions", _TEXT_ARRAY, nullable=False),
        sa.ForeignKeyConstraint(
            ["advisory_id"],
            ["advisories.id"],
            name="fk_advisory_affected_advisory_id_advisories",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_advisory_affected"),
        sa.UniqueConstraint(
            "advisory_id",
            "ecosystem",
            "package_name",
            name="uq_advisory_affected_advisory_id_ecosystem_package_name",
        ),
    )
    op.create_index(
        "ix_advisory_affected_lookup", "advisory_affected", ["ecosystem", "package_name"]
    )
    op.create_index("ix_advisory_affected_purl_base", "advisory_affected", ["purl_base"])

    op.create_table(
        "vulnerable_symbols",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("advisory_id", sa.String(length=64), nullable=False),
        sa.Column("ecosystem", sa.String(length=64), nullable=False),
        sa.Column("package_name", sa.Text(), nullable=False),
        sa.Column("symbol", sa.Text(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=8), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("fix_commit", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "kind IN ('function', 'method', 'class', 'module')",
            name="ck_vulnerable_symbols_kind",
        ),
        sa.CheckConstraint(
            "source IN ('curated', 'fix_commit', 'osv_ecosystem_specific', 'tag_diff')",
            name="ck_vulnerable_symbols_source",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_vulnerable_symbols_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["advisory_id"],
            ["advisories.id"],
            name="fk_vulnerable_symbols_advisory_id_advisories",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_vulnerable_symbols"),
        sa.UniqueConstraint(
            "advisory_id",
            "package_name",
            "symbol",
            name="uq_vulnerable_symbols_advisory_id_package_name_symbol",
        ),
    )
    op.create_index(
        "ix_vulnerable_symbols_lookup", "vulnerable_symbols", ["ecosystem", "package_name"]
    )

    op.create_table(
        "advisory_snapshots",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("ecosystems", _TEXT_ARRAY, nullable=False),
        sa.Column("counts", postgresql.JSONB(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_advisory_snapshots"),
        sa.UniqueConstraint("content_sha256", name="uq_advisory_snapshots_content_sha256"),
    )

    op.create_table(
        "package_callgraphs",
        sa.Column("ecosystem", sa.String(length=64), nullable=False),
        sa.Column("package_name", sa.Text(), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("builder_version", sa.String(length=32), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=True),
        sa.Column("node_count", sa.Integer(), nullable=True),
        sa.Column("edge_count", sa.Integer(), nullable=True),
        sa.Column("unresolved_call_ratio", sa.Float(), nullable=True),
        sa.Column("status", sa.String(length=16), server_default="building", nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("built_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('building', 'ready', 'failed')",
            name="ck_package_callgraphs_status",
        ),
        sa.PrimaryKeyConstraint(
            "ecosystem",
            "package_name",
            "version",
            "builder_version",
            name="pk_package_callgraphs",
        ),
    )
    op.create_index("ix_package_callgraphs_status", "package_callgraphs", ["status"])


def downgrade() -> None:
    op.drop_table("package_callgraphs")
    op.drop_table("advisory_snapshots")
    op.drop_table("vulnerable_symbols")
    op.drop_table("advisory_affected")
    op.drop_table("advisories")
