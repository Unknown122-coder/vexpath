"""Record why symbol extraction ended where it did, and how often it was tried.

Extraction reaches the network: it fetches an advisory's fix commit from the
upstream repository. That fails for reasons that have nothing to do with the
advisory, so the job needs somewhere to record what happened and how many times
it has tried. Without the attempt count, a permanently broken advisory is
retried on every run forever while advisories never tried once wait behind it.

``symbols_detail`` is the plain-language reason. It is shown by
``vexpath advisory show`` so that a finding left under investigation can be
explained without re-running anything.

Revision ID: 0003_extraction_bookkeeping
Revises: 0002_manual_symbol_source
Created: 2026-11-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_extraction_bookkeeping"
down_revision: str | None = "0002_manual_symbol_source"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("advisories", sa.Column("symbols_detail", sa.Text(), nullable=True))
    op.add_column(
        "advisories",
        sa.Column(
            "symbols_attempts", sa.SmallInteger(), server_default="0", nullable=False
        ),
    )
    op.add_column(
        "advisories",
        sa.Column("symbols_attempted_at", sa.DateTime(timezone=True), nullable=True),
    )
    # The work queue, as a partial index. Most rows leave it permanently once
    # extracted, so indexing only the ones still waiting keeps it small as the
    # corpus grows past a hundred thousand advisories.
    op.create_index(
        "ix_advisories_extraction_queue",
        "advisories",
        ["symbols_attempts", "modified_at"],
        postgresql_where=sa.text("symbols_status IN ('pending', 'failed')"),
    )


def downgrade() -> None:
    op.drop_index("ix_advisories_extraction_queue", table_name="advisories")
    op.drop_column("advisories", "symbols_attempted_at")
    op.drop_column("advisories", "symbols_attempts")
    op.drop_column("advisories", "symbols_detail")
