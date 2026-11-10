"""Tenant tables, and the row-level security that keeps them apart.

One organisation reading another's dependency inventory is the worst thing
this platform could do. A source inventory names every library a company
depends on and every version it is behind on, which is a map of where to
attack them.

So isolation is not a ``WHERE`` clause. A filter that has to be remembered is
a filter that will one day be forgotten, in a new endpoint written in a hurry,
and nothing will fail until a customer notices. Postgres enforces it instead,
on every statement, including the ones nobody has written yet.

Three things make that real, and leaving out any one of them makes the rest
decorative:

1. **Policies on every tenant table**, comparing ``org_id`` against a session
   setting the request sets and nothing else can reach.
2. **FORCE ROW LEVEL SECURITY**, because a table's owner is exempt from its
   own policies by default and the owner is who runs the migrations.
3. **A non-privileged role for the application.** A superuser bypasses
   row-level security entirely, and the local development user is one. The
   application connects as the owner and immediately ``SET ROLE`` to
   ``vexpath_app``, which holds data privileges and no exemptions.

The public read path is a separate setting rather than a relaxation of the
first. A page serving a public report must not be able to serve it with a
tenant's context attached, so the two conditions are written apart and neither
implies the other.

Revision ID: 0004_tenant_tables_and_rls
Revises: 0003_extraction_bookkeeping
Created: 2026-11-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_tenant_tables_and_rls"
down_revision: str | None = "0003_extraction_bookkeeping"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TEXT_ARRAY = postgresql.ARRAY(sa.Text())

#: The role the application runs as. Not a login role: the application
#: connects with the owner's credentials and switches, so there is no second
#: password to provision, rotate or leak.
APP_ROLE = "vexpath_app"

#: The setting every policy reads.
ORG_SETTING = "vexpath.org_id"

#: The setting that opens the public read path.
PUBLIC_SETTING = "vexpath.public"

#: Tables the policies cover. Each needs ``org_id``; the migration fails loudly
#: rather than skipping one, because a tenant table with no policy is readable
#: by every tenant.
TENANT_TABLES = (
    "orgs",
    "users",
    "users_orgs",
    "api_keys",
    "projects",
    "scans",
    "sboms",
    "components",
    "component_edges",
    "findings",
    "reachability_results",
    "vex_statements",
    "attestations",
    "policies",
    "policy_evaluations",
    "suppressions",
    "audit_log",
)

#: Tables a public report page may read, and only when the public setting is
#: on. Deliberately short: a public report shows the project, its scans and
#: their findings with evidence. It never shows who the users are, what the
#: API keys are, or what has been suppressed and why.
PUBLIC_READABLE = (
    "projects",
    "scans",
    "sboms",
    "components",
    "component_edges",
    "findings",
    "reachability_results",
    "vex_statements",
    "attestations",
)


def upgrade() -> None:
    _create_tables()
    _create_role()
    _enable_row_level_security()


def _create_tables() -> None:
    op.create_table(
        "orgs",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_orgs"),
        sa.UniqueConstraint("slug", name="uq_orgs_slug"),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("provider", sa.String(length=32), server_default="github", nullable=False),
        sa.Column("provider_subject", sa.Text(), nullable=False),
        sa.Column("login", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_users_org_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("provider", "provider_subject", name="uq_users_provider_subject"),
    )

    op.create_table(
        "users_orgs",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("user_id", sa.String(length=26), nullable=False),
        sa.Column("role", sa.String(length=16), server_default="member", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("role IN ('owner', 'member')", name="ck_users_orgs_role"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_users_orgs_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_users_orgs_user_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_users_orgs"),
        sa.UniqueConstraint("org_id", "user_id", name="uq_users_orgs_org_user"),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.String(length=26), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_api_keys_org_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
    )
    op.create_index("ix_api_keys_org", "api_keys", ["org_id"])

    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("repo_url", sa.Text(), nullable=True),
        sa.Column("default_branch", sa.Text(), server_default="main", nullable=False),
        sa.Column("visibility", sa.String(length=16), server_default="private", nullable=False),
        sa.Column("entry_points", postgresql.JSONB(), nullable=False),
        sa.Column("settings", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "visibility IN ('private', 'public')", name="ck_projects_visibility"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_projects_org_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_projects"),
        sa.UniqueConstraint("org_id", "slug", name="uq_projects_org_slug"),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("project_id", sa.String(length=26), nullable=False),
        sa.Column("mode", sa.String(length=16), server_default="cli", nullable=False),
        sa.Column("git_ref", sa.Text(), nullable=True),
        sa.Column("git_sha", sa.String(length=64), nullable=True),
        sa.Column("advisory_snapshot_id", sa.String(length=26), nullable=True),
        sa.Column("core_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="queued", nullable=False),
        sa.Column("summary", postgresql.JSONB(), nullable=False),
        sa.Column("diff_vs_previous", postgresql.JSONB(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("mode IN ('cli', 'action', 'hosted')", name="ck_scans_mode"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')", name="ck_scans_status"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_scans_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name="fk_scans_project_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("ix_scans_project_created", "scans", ["project_id", "created_at"])

    op.create_table(
        "sboms",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("scan_id", sa.String(length=26), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=True),
        sa.Column("document_hash", sa.String(length=64), nullable=False),
        sa.Column("generated_by", sa.String(length=32), server_default="vexpath", nullable=False),
        sa.Column("component_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_sboms_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_sboms_scan_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_sboms"),
        sa.UniqueConstraint("scan_id", name="uq_sboms_scan_id"),
    )

    op.create_table(
        "components",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("sbom_id", sa.String(length=26), nullable=False),
        sa.Column("purl", sa.Text(), nullable=False),
        sa.Column("ecosystem", sa.String(length=64), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("bom_ref", sa.Text(), nullable=True),
        sa.Column("direct", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("scope", sa.String(length=16), server_default="runtime", nullable=False),
        sa.Column("licenses", _TEXT_ARRAY, nullable=False),
        sa.Column("hashes", postgresql.JSONB(), nullable=False),
        sa.CheckConstraint(
            "scope IN ('runtime', 'dev', 'optional')", name="ck_components_scope"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_components_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["sbom_id"], ["sboms.id"], name="fk_components_sbom_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_components"),
        sa.UniqueConstraint("sbom_id", "purl", name="uq_components_sbom_purl"),
    )
    op.create_index("ix_components_lookup", "components", ["ecosystem", "name", "version"])

    op.create_table(
        "component_edges",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("sbom_id", sa.String(length=26), nullable=False),
        sa.Column("parent_component_id", sa.String(length=26), nullable=False),
        sa.Column("child_component_id", sa.String(length=26), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_component_edges_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["sbom_id"], ["sboms.id"], name="fk_component_edges_sbom_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["parent_component_id"],
            ["components.id"],
            name="fk_component_edges_parent",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["child_component_id"],
            ["components.id"],
            name="fk_component_edges_child",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_component_edges"),
        sa.UniqueConstraint(
            "sbom_id",
            "parent_component_id",
            "child_component_id",
            name="uq_component_edges_triple",
        ),
    )
    op.create_index("ix_component_edges_child", "component_edges", ["child_component_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("scan_id", sa.String(length=26), nullable=False),
        sa.Column("component_id", sa.String(length=26), nullable=False),
        sa.Column("advisory_id", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), server_default="UNKNOWN", nullable=False),
        sa.Column("cvss_v3_score", sa.Float(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("fixed_in", sa.String(length=128), nullable=True),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("justification", sa.String(length=64), nullable=True),
        sa.Column("first_seen_scan_id", sa.String(length=26), nullable=True),
        sa.Column("suppressed_by", sa.String(length=26), nullable=True),
        sa.Column("notes", _TEXT_ARRAY, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "verdict IN ('affected', 'not_affected', 'under_investigation', 'fixed')",
            name="ck_findings_verdict",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_findings_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_findings_scan_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["component_id"],
            ["components.id"],
            name="fk_findings_component_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.UniqueConstraint(
            "scan_id", "component_id", "advisory_id", name="uq_findings_scan_component_advisory"
        ),
    )
    op.create_index("ix_findings_scan_verdict", "findings", ["scan_id", "verdict"])
    op.create_index("ix_findings_advisory", "findings", ["advisory_id"])

    op.create_table(
        "reachability_results",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("finding_id", sa.String(length=26), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=32), nullable=True),
        sa.Column("confidence", sa.String(length=8), nullable=False),
        sa.Column("matched_symbols", _TEXT_ARRAY, nullable=False),
        sa.Column("searched_symbols", _TEXT_ARRAY, nullable=False),
        sa.Column("shortest_path", postgresql.JSONB(), nullable=False),
        sa.Column("path_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("via_dynamic_edges", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("entry_points", postgresql.JSONB(), nullable=True),
        sa.Column("graph_stats", postgresql.JSONB(), nullable=True),
        sa.Column("explanation", sa.Text(), server_default="", nullable=False),
        sa.CheckConstraint(
            "status IN ('reachable_confirmed', 'reachable_possible', 'unreachable', "
            "'symbols_unknown', 'graph_incomplete')",
            name="ck_reachability_results_status",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')", name="ck_reachability_results_confidence"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_reachability_results_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_reachability_results_finding_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_reachability_results"),
        sa.UniqueConstraint("finding_id", name="uq_reachability_results_finding_id"),
    )

    op.create_table(
        "vex_statements",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("scan_id", sa.String(length=26), nullable=False),
        sa.Column("finding_id", sa.String(length=26), nullable=False),
        sa.Column("vex_document_key", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("justification", sa.String(length=64), nullable=True),
        sa.Column("impact_statement", sa.Text(), nullable=True),
        sa.Column("action_statement", sa.Text(), nullable=True),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('affected', 'not_affected', 'under_investigation', 'fixed')",
            name="ck_vex_statements_status",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_vex_statements_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_vex_statements_scan_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_vex_statements_finding_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_vex_statements"),
        sa.UniqueConstraint("finding_id", name="uq_vex_statements_finding_id"),
    )

    op.create_table(
        "attestations",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("scan_id", sa.String(length=26), nullable=False),
        sa.Column("predicate_type", sa.Text(), nullable=False),
        sa.Column("subject_digest", sa.String(length=64), nullable=False),
        sa.Column("envelope_key", sa.Text(), nullable=True),
        sa.Column("signer_identity", sa.Text(), nullable=True),
        sa.Column("rekor_log_index", sa.BigInteger(), nullable=True),
        sa.Column("rekor_uuid", sa.Text(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_attestations_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_attestations_scan_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_attestations"),
    )
    op.create_index("ix_attestations_scan", "attestations", ["scan_id"])

    op.create_table(
        "policies",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("project_id", sa.String(length=26), nullable=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("cel", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("source", sa.String(length=16), server_default="dashboard", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("source IN ('repo', 'dashboard')", name="ck_policies_source"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_policies_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name="fk_policies_project_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_policies"),
    )

    op.create_table(
        "policy_evaluations",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("scan_id", sa.String(length=26), nullable=False),
        sa.Column("policy_id", sa.String(length=26), nullable=True),
        sa.Column("cel", sa.Text(), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("violations", postgresql.JSONB(), nullable=False),
        sa.Column(
            "evaluated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_policy_evaluations_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_policy_evaluations_scan_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["policies.id"],
            name="fk_policy_evaluations_policy_id",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_policy_evaluations"),
    )
    op.create_index("ix_policy_evaluations_scan", "policy_evaluations", ["scan_id"])

    op.create_table(
        "suppressions",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("project_id", sa.String(length=26), nullable=False),
        sa.Column("advisory_id", sa.String(length=64), nullable=False),
        sa.Column("purl", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("justification", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=26), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(trim(reason)) > 0", name="ck_suppressions_reason_not_blank"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_suppressions_org_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name="fk_suppressions_project_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_suppressions"),
    )
    op.create_index("ix_suppressions_lookup", "suppressions", ["project_id", "advisory_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("org_id", sa.String(length=26), nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "actor_type IN ('user', 'api_key', 'system')", name="ck_audit_log_actor_type"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_audit_log_org_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
    )
    op.create_index("ix_audit_log_org_created", "audit_log", ["org_id", "created_at"])


def _create_role() -> None:
    """Create the role the application runs as.

    NOLOGIN on purpose. The application connects with the owner's credentials
    and immediately ``SET ROLE``, so there is no second password to provision,
    rotate or leak, and nothing can connect as this role directly.

    Created idempotently because a managed Postgres may have it already, and a
    migration that fails on a pre-existing role is a migration that cannot be
    re-run.
    """
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                CREATE ROLE {APP_ROLE} NOLOGIN NOBYPASSRLS;
            END IF;
        END
        $$;
        """
    )
    # The owner must be a member, or SET ROLE is refused.
    op.execute(f"GRANT {APP_ROLE} TO CURRENT_USER;")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE};")
    # Global tables are read-only to the application: the advisory corpus is
    # written by the sync worker running as the owner, and an endpoint that
    # could rewrite an advisory could change a verdict.
    for table in ("advisories", "advisory_affected", "vulnerable_symbols", "advisory_snapshots"):
        op.execute(f"GRANT SELECT ON {table} TO {APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON package_callgraphs TO {APP_ROLE};")

    for table in TENANT_TABLES:
        if table == "audit_log":
            # Append-only. An actor who can delete their own audit trail has no
            # audit trail, so the privilege is simply not granted.
            op.execute(f"GRANT SELECT, INSERT ON {table} TO {APP_ROLE};")
        else:
            op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE};")


def _enable_row_level_security() -> None:
    """Enable and force policies on every tenant table.

    FORCE matters: without it the table's owner is exempt from its own
    policies, and the owner is who runs migrations and, in a small deployment,
    might be who runs the application.
    """
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")

        # The tenant policy. current_setting(..., true) returns NULL when the
        # setting is absent, and org_id = NULL is NULL rather than true, so a
        # request that forgot to set an organisation sees nothing. Failing
        # closed is the only acceptable direction here.
        op.execute(
            f"""
            CREATE POLICY {table}_tenant ON {table}
            USING (org_id = current_setting('{ORG_SETTING}', true))
            WITH CHECK (org_id = current_setting('{ORG_SETTING}', true));
            """
        )

    # The public read path, as a separate policy on a short list of tables. A
    # public report shows the project, its scans and their findings with
    # evidence. It never shows users, API keys, policies, or what has been
    # suppressed and why, so those tables get no public policy at all.
    op.execute(
        f"""
        CREATE POLICY projects_public ON projects
        FOR SELECT
        USING (
            current_setting('{PUBLIC_SETTING}', true) = 'on'
            AND visibility = 'public'
        );
        """
    )
    for table in PUBLIC_READABLE:
        if table == "projects":
            continue
        # Every one of these reaches a project through scans, so the condition
        # is the same question asked one join further out: is the project this
        # row belongs to public.
        joins = {
            "scans": "p.id = scans.project_id",
            "sboms": "s.id = sboms.scan_id",
            "components": "sb.id = components.sbom_id",
            "component_edges": "sb.id = component_edges.sbom_id",
            "findings": "s.id = findings.scan_id",
            "reachability_results": "f.id = reachability_results.finding_id",
            "vex_statements": "s.id = vex_statements.scan_id",
            "attestations": "s.id = attestations.scan_id",
        }
        condition = _public_condition(table, joins[table])
        op.execute(
            f"""
            CREATE POLICY {table}_public ON {table}
            FOR SELECT
            USING (
                current_setting('{PUBLIC_SETTING}', true) = 'on'
                AND {condition}
            );
            """
        )


def _public_condition(table: str, join: str) -> str:
    """The "belongs to a public project" test for one table.

    Written as an EXISTS against the chain up to ``projects`` rather than as a
    denormalised flag on every row. A flag would have to be kept in step on
    every write, and the one time it is not, a private project's findings
    become world-readable.
    """
    chains = {
        "scans": f"EXISTS (SELECT 1 FROM projects p WHERE {join} AND p.visibility = 'public')",
        "sboms": (
            "EXISTS (SELECT 1 FROM scans s JOIN projects p ON p.id = s.project_id "
            f"WHERE {join} AND p.visibility = 'public')"
        ),
        "findings": (
            "EXISTS (SELECT 1 FROM scans s JOIN projects p ON p.id = s.project_id "
            f"WHERE {join} AND p.visibility = 'public')"
        ),
        "vex_statements": (
            "EXISTS (SELECT 1 FROM scans s JOIN projects p ON p.id = s.project_id "
            f"WHERE {join} AND p.visibility = 'public')"
        ),
        "attestations": (
            "EXISTS (SELECT 1 FROM scans s JOIN projects p ON p.id = s.project_id "
            f"WHERE {join} AND p.visibility = 'public')"
        ),
        "components": (
            "EXISTS (SELECT 1 FROM sboms sb JOIN scans s ON s.id = sb.scan_id "
            f"JOIN projects p ON p.id = s.project_id WHERE {join} AND p.visibility = 'public')"
        ),
        "component_edges": (
            "EXISTS (SELECT 1 FROM sboms sb JOIN scans s ON s.id = sb.scan_id "
            f"JOIN projects p ON p.id = s.project_id WHERE {join} AND p.visibility = 'public')"
        ),
        "reachability_results": (
            "EXISTS (SELECT 1 FROM findings f JOIN scans s ON s.id = f.scan_id "
            f"JOIN projects p ON p.id = s.project_id WHERE {join} AND p.visibility = 'public')"
        ),
    }
    return chains[table]


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {table};")
        op.execute(f"DROP POLICY IF EXISTS {table}_public ON {table};")

    for table in reversed(TENANT_TABLES):
        op.drop_table(table)

    # The role is left in place: it may own grants elsewhere, and dropping a
    # role another database object depends on fails in a way that is painful
    # to unpick.
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {APP_ROLE};")
