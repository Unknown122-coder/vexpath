"""Webhooks and their delivery log.

Two tables and one column worth explaining.

``webhooks.secret_encrypted`` holds ciphertext, not a hash. Every other
credential in this schema is stored as a SHA-256 because nothing ever needs it
back: a presented key is hashed and compared. A webhook secret is a *shared*
secret used to compute an HMAC on each delivery, so the server has to read it.
It is encrypted with a key derived from ``VEXPATH_SECRET_KEY``, which defends a
leaked backup or an open replica and does not pretend to defend an attacker who
has the process.

``webhook_deliveries`` records the outcome and the payload's digest, never the
payload. A delivery carries findings; keeping a second copy of them in a log
table doubles the places a leak can come from and adds nothing a digest does
not already give for "was this the same body".

Revision ID: 0006_webhooks
Revises: 0005_sessions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY

from vexpath_db.tables import APP_ROLE, ORG_SETTING

revision: str = "0006_webhooks"
down_revision: str | None = "0005_sessions"
branch_labels: str | None = None
depends_on: str | None = None

TABLES = ("webhooks", "webhook_deliveries")


def upgrade() -> None:
    op.create_table(
        "webhooks",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("project_id", sa.String(length=26), nullable=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("secret_encrypted", sa.Text(), nullable=False),
        sa.Column("secret_fingerprint", sa.String(length=16), nullable=False),
        sa.Column("events", ARRAY(sa.Text()), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=26), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_webhooks_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name="fk_webhooks_project_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_webhooks"),
    )
    op.create_index("ix_webhooks_org", "webhooks", ["org_id"])

    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("webhook_id", sa.String(length=26), nullable=False),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'delivered', 'failed', 'refused')",
            name="ck_webhook_deliveries_status",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_webhook_deliveries_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["webhook_id"],
            ["webhooks.id"],
            name="fk_webhook_deliveries_webhook_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_webhook_deliveries"),
    )
    op.create_index(
        "ix_webhook_deliveries_hook_created", "webhook_deliveries", ["webhook_id", "created_at"]
    )

    for table in TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE};")
        # The same policy shape as every other tenant table. No public policy:
        # a webhook row holds an endpoint somebody runs and the fingerprint of
        # a shared secret, neither of which belongs on a public report page.
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant ON {table}
            USING (org_id = current_setting('{ORG_SETTING}', true))
            WITH CHECK (org_id = current_setting('{ORG_SETTING}', true));
            """
        )


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {table};")
    op.drop_index("ix_webhook_deliveries_hook_created", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
    op.drop_index("ix_webhooks_org", table_name="webhooks")
    op.drop_table("webhooks")
