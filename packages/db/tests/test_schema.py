"""Schema sanity checks.

These run without a database server: the table definitions use variant column
types so the metadata can be created on SQLite. Checks that genuinely need
Postgres are marked ``integration``.
"""

from __future__ import annotations

import ast
import re
from enum import StrEnum
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

import vexpath_db
from vexpath_core.enums import Confidence, SymbolKind, SymbolSource, SymbolsStatus
from vexpath_db.engine import normalise_url
from vexpath_db.tables import GLOBAL_TABLES, metadata

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


#: Every column whose values are a closed vocabulary, and the enum that
#: defines it. Used by both the table check and the migration check, so the two
#: cannot cover different sets of columns.
_ENUM_COLUMNS: list[tuple[str, str, type[StrEnum]]] = [
    ("advisories", "symbols_status", SymbolsStatus),
    ("vulnerable_symbols", "kind", SymbolKind),
    ("vulnerable_symbols", "source", SymbolSource),
    ("vulnerable_symbols", "confidence", Confidence),
]

#: Where the frozen migration scripts live.
ROOT_MIGRATIONS = Path(vexpath_db.__file__).parent / "migrations" / "versions"


@pytest.mark.parametrize(("table", "column", "enum_cls"), _ENUM_COLUMNS)
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


def _declared_check_constraints() -> dict[str, str]:
    """Every check constraint the migrations' ``upgrade`` functions create.

    Maps constraint name to its predicate, last declaration winning, since a
    later migration may widen an earlier constraint.

    Only ``upgrade`` is read: a ``downgrade`` recreates the *previous*
    constraint, so including it would conclude the schema is whatever the last
    rollback path says. And only check constraints are read: an index predicate
    can mention the same column with the same ``IN`` syntax without
    constraining anything.
    """
    found: dict[str, str] = {}
    for path in sorted(ROOT_MIGRATIONS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        upgrades = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "upgrade"
        ]
        for upgrade in upgrades:
            for node in ast.walk(upgrade):
                if not isinstance(node, ast.Call):
                    continue
                called = (
                    node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else (node.func.id if isinstance(node.func, ast.Name) else "")
                )
                keywords = {
                    keyword.arg: keyword.value
                    for keyword in node.keywords
                    if keyword.arg is not None
                }
                if called == "CheckConstraint":
                    name = keywords.get("name")
                    predicate = node.args[0] if node.args else None
                elif called == "create_check_constraint":
                    # op.create_check_constraint(name, table, predicate)
                    name = node.args[0] if node.args else None
                    predicate = node.args[2] if len(node.args) > 2 else None
                else:
                    continue
                if isinstance(name, ast.Constant) and isinstance(predicate, ast.Constant):
                    found[str(name.value)] = str(predicate.value)
    return found


def test_migrations_constrain_the_same_vocabulary_as_the_tables() -> None:
    """The check constraints in the migrations must match the Python enums.

    ``tables.py`` generates its constraints from the enums, so it cannot
    drift. The migrations are frozen SQL, so they can: adding an enum member
    without a migration leaves a live database rejecting a value the code
    considers valid, and nothing fails until something tries to store one.

    Read statically, so this needs no database.
    """
    declared = _declared_check_constraints()
    assert declared, "no check constraints found in the migrations"

    for table, column, enum_cls in _ENUM_COLUMNS:
        name = f"ck_{table}_{column}"
        predicate = declared.get(name)
        assert predicate, f"no migration creates {name}; declared: {sorted(declared)}"
        allowed = set(re.findall(r"'([^']+)'", predicate))
        expected = {member.value for member in enum_cls}
        assert allowed == expected, (
            f"{name} allows {sorted(allowed)} but {enum_cls.__name__} is "
            f"{sorted(expected)}; add a migration"
        )


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
