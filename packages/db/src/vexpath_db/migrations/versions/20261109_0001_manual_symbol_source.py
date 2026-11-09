"""Allow a manually supplied vulnerable symbol.

``vexpath reach --symbol`` lets an operator name a symbol when an advisory
carries no recoverable fix commit. Those symbols are recorded with a ``manual``
provenance so a reader can see that nothing verified them, and the column's
check constraint has to admit the value or storing one would fail.

The constraint is recreated rather than altered: Postgres has no way to extend
a check constraint in place, and dropping and adding is a metadata-only
operation on a column that already satisfies the wider predicate.

Revision ID: 0002_manual_symbol_source
Revises: 0001_global_advisory
Created: 2026-11-09
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_manual_symbol_source"
down_revision: str | None = "0001_global_advisory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

def upgrade() -> None:
    # The predicate is written out rather than built from the enum. A
    # migration is a record of what was done to a database, and it has to keep
    # meaning that after the enum moves on.
    op.drop_constraint("ck_vulnerable_symbols_source", "vulnerable_symbols", type_="check")
    op.create_check_constraint(
        "ck_vulnerable_symbols_source",
        "vulnerable_symbols",
        "source IN ('curated', 'fix_commit', 'osv_ecosystem_specific', 'tag_diff', 'manual')",
    )


def downgrade() -> None:
    # Rows that only the wider predicate allowed would violate the narrower
    # one, so they go first. They are re-extractable from the advisory corpus,
    # and a downgrade that fails halfway is worse than one that drops them.
    op.execute("DELETE FROM vulnerable_symbols WHERE source = 'manual'")
    op.drop_constraint("ck_vulnerable_symbols_source", "vulnerable_symbols", type_="check")
    op.create_check_constraint(
        "ck_vulnerable_symbols_source",
        "vulnerable_symbols",
        "source IN ('curated', 'fix_commit', 'osv_ecosystem_specific', 'tag_diff')",
    )
