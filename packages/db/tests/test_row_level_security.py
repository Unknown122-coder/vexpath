"""Tenant isolation, table by table.

One organisation reading another's dependency inventory is the worst thing
this platform could do: an inventory names every library a company depends on
and every version it is behind on, which is a map of where to attack them.

So these tests are adversarial rather than illustrative. For every tenant
table they ask for the other organisation's rows directly, by identifier,
which is what a bug in a new endpoint would do. They also ask with no context
at all, because a request that forgot to establish one must see nothing rather
than everything.

The structural test is the one that keeps working as the schema grows: every
table the metadata calls a tenant table must have row-level security enabled,
forced, and a policy. A table added without those three is a table every
tenant can read, and nothing else in the suite would notice.

Needs a real Postgres: row-level security does not exist in SQLite, so testing
this anywhere else would prove nothing at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text

from vexpath_db.engine import create_sync_engine
from vexpath_db.tables import APP_ROLE, TENANT_TABLE_NAMES
from vexpath_db.tenancy import (
    TenancyError,
    current_org,
    is_public_context,
    public_context,
    tenant_context,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy import Engine

pytestmark = pytest.mark.integration

#: Marks the rows these tests own, so running the suite does not disturb a
#: database someone is using.
MARKER = "ZZRLS"
ORG_A = f"{MARKER}A"
ORG_B = f"{MARKER}B"

#: Tables a public report page may read. Everything else must stay invisible
#: on the public path however the query is written.
PUBLIC_READABLE = frozenset(
    {
        "projects",
        "scans",
        "sboms",
        "components",
        "component_edges",
        "findings",
        "reachability_results",
        "vex_statements",
        "attestations",
    }
)


@pytest.fixture
def engine(integration_database_url: str) -> Iterator[Engine]:
    engine = create_sync_engine(integration_database_url, connect_timeout=3)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1 FROM orgs LIMIT 1"))
    except Exception as exc:  # noqa: BLE001 - a missing database skips, not fails
        engine.dispose()
        pytest.skip(f"integration database unavailable: {type(exc).__name__}: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture
def seeded(engine: Engine) -> Iterator[Engine]:
    """One row in every tenant table, for each of two organisations."""
    _wipe(engine)
    _seed(engine, ORG_A, visibility="public")
    _seed(engine, ORG_B, visibility="private")
    yield engine
    _wipe(engine)


def _wipe(engine: Engine) -> None:
    with engine.begin() as connection:
        # As the owner, with a context per organisation, because the owner is
        # subject to the policies too: the tables are FORCE ROW LEVEL SECURITY.
        for org in (ORG_A, ORG_B):
            connection.execute(
                text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org}
            )
            connection.execute(text("DELETE FROM orgs WHERE id = :org"), {"org": org})


def _seed(engine: Engine, org: str, *, visibility: str) -> None:
    """Insert one row in every tenant table for one organisation."""
    now = datetime.now(UTC)
    rows: list[tuple[str, dict[str, Any]]] = [
        (
            "INSERT INTO orgs (id, org_id, slug, name) VALUES (:id, :org, :slug, :name)",
            {"id": org, "org": org, "slug": org, "name": org},
        ),
        (
            "INSERT INTO users (id, org_id, provider, provider_subject, login) "
            "VALUES (:id, :org, 'github', :subject, :login)",
            {"id": f"{org}-user", "org": org, "subject": f"{org}-sub", "login": f"{org}-login"},
        ),
        (
            "INSERT INTO users_orgs (id, org_id, user_id, role) VALUES (:id, :org, :user, 'owner')",
            {"id": f"{org}-member", "org": org, "user": f"{org}-user"},
        ),
        (
            "INSERT INTO api_keys (id, org_id, name, key_hash, prefix) "
            "VALUES (:id, :org, 'ci', :hash, 'vexpath_live_zz')",
            {"id": f"{org}-key", "org": org, "hash": (org + "0").ljust(64, "0")[:64]},
        ),
        (
            # A session is a browser credential and a tenant row like any
            # other: one organisation must not be able to read or forge
            # another's, which would be account takeover rather than a leak.
            "INSERT INTO sessions (id, org_id, user_id, token_hash, expires_at) "
            "VALUES (:id, :org, :user, :hash, :expires)",
            {
                "id": f"{org}-session",
                "org": org,
                "user": f"{org}-user",
                "hash": (org + "1").ljust(64, "1")[:64],
                "expires": now + timedelta(days=1),
            },
        ),
        (
            "INSERT INTO projects (id, org_id, slug, visibility, entry_points, settings) "
            "VALUES (:id, :org, 'svc', :visibility, '[]', '{}')",
            {"id": f"{org}-project", "org": org, "visibility": visibility},
        ),
        (
            "INSERT INTO scans (id, org_id, project_id, core_version, summary) "
            "VALUES (:id, :org, :project, '0.0.1', '{}')",
            {"id": f"{org}-scan", "org": org, "project": f"{org}-project"},
        ),
        (
            "INSERT INTO sboms (id, org_id, scan_id, format, document_hash) "
            "VALUES (:id, :org, :scan, 'cyclonedx-1.6-json', :hash)",
            {"id": f"{org}-sbom", "org": org, "scan": f"{org}-scan", "hash": "a" * 64},
        ),
        (
            "INSERT INTO components (id, org_id, sbom_id, purl, ecosystem, name, version, "
            "licenses, hashes) VALUES (:id, :org, :sbom, :purl, 'PyPI', 'lib', '1.0.0', "
            "'{}', '{}')",
            {
                "id": f"{org}-component",
                "org": org,
                "sbom": f"{org}-sbom",
                "purl": f"pkg:pypi/lib@1.0.0?org={org}",
            },
        ),
        (
            "INSERT INTO component_edges (id, org_id, sbom_id, parent_component_id, "
            "child_component_id) VALUES (:id, :org, :sbom, :component, :component)",
            {
                "id": f"{org}-edge",
                "org": org,
                "sbom": f"{org}-sbom",
                "component": f"{org}-component",
            },
        ),
        (
            "INSERT INTO findings (id, org_id, scan_id, component_id, advisory_id, verdict, "
            "notes) VALUES (:id, :org, :scan, :component, 'CVE-2026-0001', 'affected', '{}')",
            {
                "id": f"{org}-finding",
                "org": org,
                "scan": f"{org}-scan",
                "component": f"{org}-component",
            },
        ),
        (
            "INSERT INTO reachability_results (id, org_id, finding_id, status, confidence, "
            "matched_symbols, searched_symbols, shortest_path) "
            "VALUES (:id, :org, :finding, 'unreachable', 'high', '{}', '{}', '[]')",
            {"id": f"{org}-reach", "org": org, "finding": f"{org}-finding"},
        ),
        (
            "INSERT INTO vex_statements (id, org_id, scan_id, finding_id, status) "
            "VALUES (:id, :org, :scan, :finding, 'not_affected')",
            {
                "id": f"{org}-vex",
                "org": org,
                "scan": f"{org}-scan",
                "finding": f"{org}-finding",
            },
        ),
        (
            "INSERT INTO attestations (id, org_id, scan_id, predicate_type, subject_digest) "
            "VALUES (:id, :org, :scan, 'https://openvex.dev/ns/v0.2.0', :digest)",
            {"id": f"{org}-att", "org": org, "scan": f"{org}-scan", "digest": "b" * 64},
        ),
        (
            "INSERT INTO policies (id, org_id, project_id, name, cel) "
            "VALUES (:id, :org, :project, 'gate', 'false')",
            {"id": f"{org}-policy", "org": org, "project": f"{org}-project"},
        ),
        (
            "INSERT INTO policy_evaluations (id, org_id, scan_id, policy_id, cel, passed, "
            "violations) VALUES (:id, :org, :scan, :policy, 'false', true, '[]')",
            {
                "id": f"{org}-eval",
                "org": org,
                "scan": f"{org}-scan",
                "policy": f"{org}-policy",
            },
        ),
        (
            "INSERT INTO suppressions (id, org_id, project_id, advisory_id, reason, expires_at) "
            "VALUES (:id, :org, :project, 'CVE-2026-0001', 'reviewed', :expires)",
            {
                "id": f"{org}-supp",
                "org": org,
                "project": f"{org}-project",
                "expires": now + timedelta(days=30),
            },
        ),
        (
            # A webhook row holds an endpoint somebody runs and the
            # fingerprint of a shared secret. One organisation reading
            # another's would hand over where to send forged deliveries.
            "INSERT INTO webhooks (id, org_id, url, secret_encrypted, "
            "secret_fingerprint, events) "
            "VALUES (:id, :org, :url, 'ciphertext', 'abc123', '{ping}')",
            {"id": f"{org}-hook", "org": org, "url": f"https://example.com/{org}"},
        ),
        (
            "INSERT INTO webhook_deliveries (id, org_id, webhook_id, event, status, "
            "payload_sha256) VALUES (:id, :org, :hook, 'ping', 'delivered', :digest)",
            {
                "id": f"{org}-delivery",
                "org": org,
                "hook": f"{org}-hook",
                "digest": "f" * 64,
            },
        ),
        (
            "INSERT INTO audit_log (id, org_id, actor_type, action, metadata) "
            "VALUES (:id, :org, 'system', 'seeded', '{}')",
            {"id": f"{org}-audit", "org": org},
        ),
    ]

    with engine.begin() as connection:
        connection.execute(text("SELECT set_config('vexpath.org_id', :org, true)"), {"org": org})
        for statement, parameters in rows:
            connection.execute(text(statement), parameters)


# --- The structural guard -------------------------------------------------


def test_every_tenant_table_is_protected(engine: Engine) -> None:
    """The test that keeps working as the schema grows.

    A table added without row-level security is a table every tenant can read,
    and nothing else in this suite would notice.
    """
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relname = ANY(:names)
                """
            ),
            {"names": list(TENANT_TABLE_NAMES)},
        ).all()
        policies = connection.execute(
            text("SELECT tablename, policyname FROM pg_policies WHERE schemaname = 'public'")
        ).all()

    found = {name: (enabled, forced) for name, enabled, forced in rows}
    assert set(found) == set(TENANT_TABLE_NAMES), "a tenant table is missing from the database"

    by_table: dict[str, set[str]] = {}
    for table, policy in policies:
        by_table.setdefault(table, set()).add(policy)

    for table in TENANT_TABLE_NAMES:
        enabled, forced = found[table]
        assert enabled, f"{table} does not have row-level security enabled"
        # Without FORCE, the table's owner is exempt from its own policies, and
        # the owner is who runs migrations.
        assert forced, f"{table} does not force row-level security on its owner"
        assert f"{table}_tenant" in by_table.get(table, set()), f"{table} has no tenant policy"


def test_the_application_role_cannot_bypass_policies(engine: Engine) -> None:
    """A superuser ignores row-level security entirely.

    The local development user is one, so the application switching to a
    non-privileged role is what makes any of this real.
    """
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = :name"),
            {"name": APP_ROLE},
        ).one()
    assert row.rolsuper is False
    assert row.rolbypassrls is False
    # NOLOGIN: the application connects as the owner and switches, so there is
    # no second password to provision or leak.
    assert row.rolcanlogin is False


def test_the_context_helper_actually_switches_role(seeded: Engine) -> None:
    with seeded.begin() as connection, tenant_context(connection, ORG_A) as scoped:
        assert scoped.execute(text("SELECT current_user")).scalar_one() == APP_ROLE
        assert current_org(scoped) == ORG_A
        assert not is_public_context(scoped)


# --- Reading across the boundary ------------------------------------------


@pytest.mark.parametrize("table", TENANT_TABLE_NAMES)
def test_one_organisation_cannot_read_anothers_rows(seeded: Engine, table: str) -> None:
    """Asked directly, by identifier, which is what a bug would do."""
    with seeded.begin() as connection, tenant_context(connection, ORG_A) as scoped:
        mine = scoped.execute(
            text(f"SELECT count(*) FROM {table} WHERE org_id = :org"), {"org": ORG_A}
        ).scalar_one()
        theirs = scoped.execute(
            text(f"SELECT count(*) FROM {table} WHERE org_id = :org"), {"org": ORG_B}
        ).scalar_one()

    assert mine == 1, f"{table}: the organisation cannot see its own row"
    assert theirs == 0, f"{table}: one organisation can read another's rows"


@pytest.mark.parametrize("table", TENANT_TABLE_NAMES)
def test_a_request_with_no_context_sees_nothing(seeded: Engine, table: str) -> None:
    """Failing closed is the only acceptable direction.

    ``current_setting`` returns NULL when the setting is absent, and
    ``org_id = NULL`` is NULL rather than true, so a request that forgot to
    establish a context sees nothing instead of everything.
    """
    with seeded.begin() as connection:
        connection.execute(text(f"SET LOCAL ROLE {APP_ROLE}"))
        visible = connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
    assert visible == 0, f"{table}: visible with no tenant context"


@pytest.mark.parametrize("table", TENANT_TABLE_NAMES)
def test_one_organisation_cannot_write_into_another(seeded: Engine, table: str) -> None:
    """The WITH CHECK half of each policy.

    Without it a tenant could insert rows carrying someone else's identifier,
    which is a way to corrupt another account rather than to read it.
    """
    from sqlalchemy.exc import ProgrammingError

    # audit_log is refused earlier and harder: it has no UPDATE privilege at
    # all, because an actor who can rewrite their own audit trail has none.
    # Either refusal is correct, and accepting only one would make this test
    # about which mechanism fired rather than about the write being stopped.
    with (
        seeded.begin() as connection,
        tenant_context(connection, ORG_A) as scoped,
        pytest.raises(ProgrammingError, match=r"row-level security|permission denied"),
    ):
        scoped.execute(
            text(f"UPDATE {table} SET org_id = :org WHERE org_id = :mine"),
            {"org": ORG_B, "mine": ORG_A},
        )


def test_an_update_cannot_move_a_row_out_of_its_organisation(seeded: Engine) -> None:
    with seeded.begin() as connection, tenant_context(connection, ORG_A) as scoped:
        changed = scoped.execute(
            text("UPDATE projects SET slug = 'renamed' WHERE org_id = :org"), {"org": ORG_B}
        )
        # Not an error: the row simply is not visible, so nothing matches.
        assert changed.rowcount == 0


def test_a_delete_cannot_reach_across_the_boundary(seeded: Engine) -> None:
    with seeded.begin() as connection, tenant_context(connection, ORG_A) as scoped:
        deleted = scoped.execute(text("DELETE FROM findings WHERE org_id = :org"), {"org": ORG_B})
        assert deleted.rowcount == 0

    with seeded.begin() as connection, tenant_context(connection, ORG_B) as scoped:
        assert scoped.execute(text("SELECT count(*) FROM findings")).scalar_one() == 1


def test_a_join_does_not_leak_what_a_select_cannot_reach(seeded: Engine) -> None:
    """Policies apply per table, so a join is filtered at every step."""
    with seeded.begin() as connection, tenant_context(connection, ORG_A) as scoped:
        rows = scoped.execute(
            text(
                """
                SELECT f.id, c.purl FROM findings f
                JOIN components c ON c.id = f.component_id
                """
            )
        ).all()
    assert [row.id for row in rows] == [f"{ORG_A}-finding"]
    assert ORG_B not in rows[0].purl


def test_an_aggregate_cannot_count_the_other_organisation(seeded: Engine) -> None:
    """A count is a read, and a leaked count is still a leak."""
    with seeded.begin() as connection, tenant_context(connection, ORG_A) as scoped:
        assert scoped.execute(text("SELECT count(*) FROM orgs")).scalar_one() == 1


def test_an_empty_organisation_identifier_is_refused(seeded: Engine) -> None:
    """It would match no rows, which is safe but indistinguishable from an
    account that genuinely has nothing."""
    with (
        seeded.begin() as connection,
        pytest.raises(TenancyError, match="organisation identifier"),
        tenant_context(connection, "  "),
    ):
        pass


# --- The public read path -------------------------------------------------


def test_the_public_path_shows_only_public_projects(seeded: Engine) -> None:
    with seeded.begin() as connection, public_context(connection) as scoped:
        rows = scoped.execute(
            text("SELECT id, visibility FROM projects WHERE org_id LIKE :marker"),
            {"marker": f"{MARKER}%"},
        ).all()
    assert [(row.id, row.visibility) for row in rows] == [(f"{ORG_A}-project", "public")]


@pytest.mark.parametrize("table", sorted(set(TENANT_TABLE_NAMES) - PUBLIC_READABLE))
def test_the_public_path_cannot_reach_private_tables(seeded: Engine, table: str) -> None:
    """Users, API keys, policies and suppressions have no public policy at all.

    Which of those matters most is arguable; that none of them is published is
    not. A suppression in particular says "we know about this and chose not to
    fix it", which is an invitation.
    """
    with seeded.begin() as connection, public_context(connection) as scoped:
        visible = scoped.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
    assert visible == 0, f"{table}: readable on the public path"


@pytest.mark.parametrize("table", sorted(PUBLIC_READABLE - {"projects"}))
def test_the_public_path_shows_rows_of_a_public_project_only(seeded: Engine, table: str) -> None:
    """Each of these reaches a project through a chain of joins.

    The condition is an EXISTS up that chain rather than a flag on the row,
    because a flag has to be kept in step on every write and the one time it
    is not, a private project's findings become world-readable.
    """
    with seeded.begin() as connection, public_context(connection) as scoped:
        rows = (
            scoped.execute(
                text(f"SELECT org_id FROM {table} WHERE org_id LIKE :marker"),
                {"marker": f"{MARKER}%"},
            )
            .scalars()
            .all()
        )
    assert rows == [ORG_A], f"{table}: public path returned {rows}"


def test_the_public_path_carries_no_tenant_context(seeded: Engine) -> None:
    """A page serving a public report must not hold a tenant's context too.

    Both at once would let a public page serve one organisation's private
    findings, so entering either clears the other.
    """
    with (
        seeded.begin() as connection,
        tenant_context(connection, ORG_B) as scoped,
        public_context(scoped) as published,
    ):
        assert current_org(published) == ""
        assert is_public_context(published)
        visible = published.execute(
            text("SELECT count(*) FROM projects WHERE org_id = :org"), {"org": ORG_B}
        ).scalar_one()
        assert visible == 0


def test_entering_a_tenant_context_clears_the_public_one(seeded: Engine) -> None:
    with (
        seeded.begin() as connection,
        public_context(connection) as published,
        tenant_context(published, ORG_B) as scoped,
    ):
        assert not is_public_context(scoped)
        assert current_org(scoped) == ORG_B
        # The other organisation's public project is now invisible, because a
        # tenant context answers a different question from a public one.
        assert scoped.execute(text("SELECT count(*) FROM projects")).scalar_one() == 1


def test_the_public_path_cannot_write(seeded: Engine) -> None:
    """Nothing published is editable by the people reading it."""
    from sqlalchemy.exc import ProgrammingError

    with (
        seeded.begin() as connection,
        public_context(connection) as scoped,
        pytest.raises(ProgrammingError, match="row-level security"),
    ):
        scoped.execute(
            text(
                "INSERT INTO projects (id, org_id, slug, entry_points, settings) "
                "VALUES ('x', 'x', 'x', '[]', '{}')"
            )
        )


# --- The audit log --------------------------------------------------------


def test_the_audit_log_cannot_be_rewritten(seeded: Engine) -> None:
    """An actor who can delete their own audit trail has no audit trail.

    Enforced by withholding the privilege rather than by a policy, so it holds
    for any statement anyone writes.
    """
    from sqlalchemy.exc import ProgrammingError

    for statement in ("DELETE FROM audit_log", "UPDATE audit_log SET action = 'tampered'"):
        with (
            seeded.begin() as connection,
            tenant_context(connection, ORG_A) as scoped,
            pytest.raises(ProgrammingError, match="permission denied"),
        ):
            scoped.execute(text(statement))


def test_the_audit_log_can_still_be_appended_to(seeded: Engine) -> None:
    with seeded.begin() as connection, tenant_context(connection, ORG_A) as scoped:
        scoped.execute(
            text(
                "INSERT INTO audit_log (id, org_id, actor_type, action, metadata) "
                "VALUES (:id, :org, 'user', 'did something', '{}')"
            ),
            {"id": f"{ORG_A}-audit-2", "org": ORG_A},
        )
        assert scoped.execute(text("SELECT count(*) FROM audit_log")).scalar_one() == 2


# --- The advisory corpus --------------------------------------------------


def test_the_application_cannot_rewrite_an_advisory(seeded: Engine) -> None:
    """An endpoint that could change an advisory could change a verdict.

    The corpus is written by the sync worker running as the owner; the
    application reads it.
    """
    from sqlalchemy.exc import ProgrammingError

    with seeded.begin() as connection, tenant_context(connection, ORG_A) as scoped:
        assert scoped.execute(text("SELECT count(*) FROM advisories")).scalar_one() >= 0

    with (
        seeded.begin() as connection,
        tenant_context(connection, ORG_A) as scoped,
        pytest.raises(ProgrammingError, match="permission denied"),
    ):
        scoped.execute(text("UPDATE advisories SET severity = 'LOW'"))
