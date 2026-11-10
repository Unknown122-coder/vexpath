"""Browser sessions.

An API key identifies a CI job; a session identifies a person using a browser.
They are deliberately separate credentials with separate tables, because the
browser sends its credential automatically on every request to this origin and
a CI job does not. That one difference is the whole reason cross-site request
forgery exists, and keeping the two apart means the JSON API can refuse cookies
outright rather than defending against it.

The table stores only the hash of the cookie value, as for API keys: a database
disclosure must not hand over live sessions. The expiry is a column rather than
a convention, because a session with no expiry is a credential that outlives
the laptop it was created on.

``org_id`` is the organisation the session is *currently* acting as. A person
can belong to several, and the switch is an update to this row rather than a
new login.

Revision ID: 0005_sessions
Revises: 0004_tenant_tables_and_rls
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from vexpath_db.tables import APP_ROLE, ORG_SETTING

revision: str = "0005_sessions"
down_revision: str | None = "0004_tenant_tables_and_rls"
branch_labels: str | None = None
depends_on: str | None = None

TABLE = "sessions"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("user_id", sa.String(length=26), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_sessions_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_sessions_user_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_sessions"),
        # Unique because the hash is how a cookie is resolved, and a duplicate
        # would make that resolution ambiguous at exactly the wrong moment.
        sa.UniqueConstraint("token_hash", name="uq_sessions_token_hash"),
    )
    op.create_index("ix_sessions_user", TABLE, ["user_id"])

    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} TO {APP_ROLE};")

    # The same policy shape as every other tenant table, and for the same
    # reason: current_setting returns NULL when unset, and org_id = NULL is
    # NULL rather than true, so a request that established no organisation
    # sees nothing. There is no public policy. A session row names a person
    # and nothing about it belongs on a public report page.
    op.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"""
        CREATE POLICY {TABLE}_tenant ON {TABLE}
        USING (org_id = current_setting('{ORG_SETTING}', true))
        WITH CHECK (org_id = current_setting('{ORG_SETTING}', true));
        """
    )


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS {TABLE}_tenant ON {TABLE};")
    op.drop_index("ix_sessions_user", table_name=TABLE)
    op.drop_table(TABLE)
