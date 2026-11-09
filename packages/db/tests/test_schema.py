"""Schema sanity checks.

These run without a database server: the table definitions use variant column
types so the metadata can be created on SQLite. Checks that genuinely need
Postgres are marked ``integration``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, inspect

from sscp_core.enums import Confidence, SymbolKind, SymbolSource, SymbolsStatus
from sscp_db.engine import normalise_url
from sscp_db.tables import GLOBAL_TABLES, metadata

EXPECTED_TABLES = {
    "advisories",
    "advisory_affected",
    "vulnerable_symbols",
    "advisory_snapshots",
    "package_callgraphs",
}


def test_metadata_creates_cleanly() -> None:
    engine = create_engine("sqlite://")
    metadata.create_all(engine)
    assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES
    engine.dispose()


def test_every_table_has_a_primary_key() -> None:
    for table in GLOBAL_TABLES:
        assert table.primary_key.columns, table.name


def test_child_rows_are_removed_with_their_advisory() -> None:
    # An advisory's affected ranges and symbols belong to it entirely; leaving
    # orphans behind would let a withdrawn advisory keep producing findings.
    for table in ("advisory_affected", "vulnerable_symbols"):
        foreign_keys = list(metadata.tables[table].foreign_keys)
        assert foreign_keys, table
        assert all(fk.ondelete == "CASCADE" for fk in foreign_keys), table


def test_lookup_indexes_exist_for_the_matching_join() -> None:
    # Matching joins on (ecosystem, package_name). Without these indexes a scan
    # of a 500-dependency project becomes a sequential scan per component.
    for table in ("advisory_affected", "vulnerable_symbols"):
        indexed = {
            tuple(column.name for column in index.columns)
            for index in metadata.tables[table].indexes
        }
        assert ("ecosystem", "package_name") in indexed, table


@pytest.mark.parametrize(
    ("table", "column", "enum_cls"),
    [
        ("advisories", "symbols_status", SymbolsStatus),
        ("vulnerable_symbols", "kind", SymbolKind),
        ("vulnerable_symbols", "source", SymbolSource),
        ("vulnerable_symbols", "confidence", Confidence),
    ],
)
def test_enumerated_columns_are_constrained_to_the_python_enum(
    table: str, column: str, enum_cls: type
) -> None:
    """A vocabulary that drifts between Python and the database is a silent bug."""
    constraints = [
        constraint
        for constraint in metadata.tables[table].constraints
        if column in str(getattr(constraint, "sqltext", ""))
    ]
    assert constraints, f"{table}.{column} has no check constraint"
    clause = str(constraints[0].sqltext)  # type: ignore[attr-defined]
    for member in enum_cls:  # type: ignore[var-annotated]
        assert f"'{member.value}'" in clause, f"{member.value} missing from {table}.{column}"


def test_a_snapshot_is_identified_by_its_content() -> None:
    # Re-seeding the same corpus must not create a second snapshot row, which
    # is what keeps "this scan used snapshot X" meaningful.
    unique = {
        tuple(column.name for column in constraint.columns)
        for constraint in metadata.tables["advisory_snapshots"].constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert ("content_sha256",) in unique


def test_a_cached_call_graph_is_keyed_by_builder_version() -> None:
    # Bumping the builder must invalidate every cached graph without deleting
    # rows, so a rebuild can be rolled out gradually.
    primary_key = tuple(
        column.name for column in metadata.tables["package_callgraphs"].primary_key.columns
    )
    assert primary_key == ("ecosystem", "package_name", "version", "builder_version")


@pytest.mark.parametrize(
    "given",
    [
        "postgres://user:pw@host:5432/db",
        "postgresql://user:pw@host:5432/db",
        "postgresql+asyncpg://user:pw@host:5432/db",
    ],
)
def test_provider_connection_strings_are_rewritten_to_our_driver(given: str) -> None:
    # A URL copied from a hosting provider should just work.
    assert normalise_url(given, async_=False) == "postgresql+psycopg://user:pw@host:5432/db"
    assert normalise_url(given, async_=True) == "postgresql+psycopg://user:pw@host:5432/db"


def test_a_meaningless_url_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a database URL"):
        normalise_url("postgres://", async_=False)
