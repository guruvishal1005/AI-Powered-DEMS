"""initial schema

Revision ID: f2f3a5af0d8f
Revises:
Created: 2026-08-16 20:43:32.189416
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "f2f3a5af0d8f"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Extensions must exist before the tables that depend on them: citext backs the
    # case-insensitive users.email column, and pg_trgm supplies the gin_trgm_ops operator
    # class used by the fuzzy-search indexes below. Creating them here rather than relying on
    # container init scripts means a migration run against an empty database always succeeds.
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

    op.create_table(
        "entities",
        sa.Column(
            "type",
            sa.Enum(
                "person",
                "organization",
                "location",
                "ip_address",
                "domain",
                "url",
                "email_address",
                "phone_number",
                "username",
                "account",
                "device",
                "file_name",
                "file_path",
                "file_hash",
                "mac_address",
                "crypto_wallet",
                "payment_card",
                "cve",
                "registry_key",
                "process",
                "port",
                "user_agent",
                "credential",
                "keyword",
                name="entitytype",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("canonical_value", sa.String(length=512), nullable=False),
        sa.Column("display_value", sa.String(length=512), nullable=False),
        sa.Column("label", sa.String(length=240), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("document_frequency", sa.Integer(), nullable=False),
        sa.Column("case_count", sa.Integer(), nullable=False),
        sa.Column(
            "intel_severity",
            sa.Enum(
                "benign",
                "suspicious",
                "malicious",
                name="indicatorseverity",
                native_enum=False,
                length=48,
            ),
            nullable=True,
        ),
        sa.Column("intel_tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("intel_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_entities")),
        sa.UniqueConstraint("type", "canonical_value", name="uq_entities_type_canonical_value"),
    )
    op.create_index(op.f("ix_entities_created_at"), "entities", ["created_at"], unique=False)
    op.create_index(op.f("ix_entities_type"), "entities", ["type"], unique=False)
    op.create_index(
        "ix_entities_value_trgm",
        "entities",
        ["canonical_value"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"canonical_value": "gin_trgm_ops"},
    )
    op.create_table(
        "periodic_tasks",
        sa.Column("name", sa.String(length=96), nullable=False),
        sa.Column("task", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=24), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("run_count", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_periodic_tasks")),
        sa.UniqueConstraint("name", name=op.f("uq_periodic_tasks_name")),
    )
    op.create_index(
        op.f("ix_periodic_tasks_created_at"), "periodic_tasks", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_periodic_tasks_next_run_at"), "periodic_tasks", ["next_run_at"], unique=False
    )
    op.create_table(
        "permissions",
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=96), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_sensitive", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_permissions")),
        sa.UniqueConstraint("code", name=op.f("uq_permissions_code")),
    )
    op.create_table(
        "roles",
        sa.Column("slug", sa.String(length=48), nullable=False),
        sa.Column("name", sa.String(length=96), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("slug", name=op.f("uq_roles_slug")),
    )
    op.create_index(op.f("ix_roles_created_at"), "roles", ["created_at"], unique=False)
    op.create_table(
        "stored_objects",
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("backend", sa.String(length=32), nullable=False),
        sa.Column("storage_key", sa.String(length=512), nullable=False),
        sa.Column("encryption_algorithm", sa.String(length=32), nullable=False),
        sa.Column("nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("wrapped_key", sa.LargeBinary(length=60), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("ciphertext_size", sa.BigInteger(), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column("reference_count", sa.Integer(), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_stored_objects")),
        sa.UniqueConstraint("sha256", name=op.f("uq_stored_objects_sha256")),
    )
    op.create_index(
        op.f("ix_stored_objects_created_at"), "stored_objects", ["created_at"], unique=False
    )
    op.create_table(
        "system_health_samples",
        sa.Column("queue_depth", sa.Integer(), nullable=False),
        sa.Column("jobs_running", sa.Integer(), nullable=False),
        sa.Column("jobs_failed_24h", sa.Integer(), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("storage_bytes", sa.BigInteger(), nullable=False),
        sa.Column("integrity_failures", sa.Integer(), nullable=False),
        sa.Column("open_alerts", sa.Integer(), nullable=False),
        sa.Column(
            "worst_alert_severity",
            sa.Enum(
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                length=48,
            ),
            nullable=True,
        ),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_system_health_samples")),
    )
    op.create_index(
        op.f("ix_system_health_samples_created_at"),
        "system_health_samples",
        ["created_at"],
        unique=False,
    )
    op.create_table(
        "tags",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=True),
        sa.Column("color", sa.String(length=16), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tags")),
        sa.UniqueConstraint("name", name=op.f("uq_tags_name")),
    )
    op.create_index(op.f("ix_tags_created_at"), "tags", ["created_at"], unique=False)
    op.create_table(
        "threat_indicators",
        sa.Column(
            "type",
            sa.Enum(
                "ip_address",
                "domain",
                "url",
                "file_hash",
                "email_address",
                "crypto_wallet",
                name="indicatortype",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("canonical_value", sa.String(length=512), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "benign",
                "suspicious",
                "malicious",
                name="indicatorseverity",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("source_reference", sa.String(length=512), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("threat_actor", sa.String(length=96), nullable=True),
        sa.Column("malware_family", sa.String(length=96), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_indicators")),
        sa.UniqueConstraint(
            "type", "canonical_value", "source", name="uq_threat_indicators_type_value_source"
        ),
    )
    op.create_index(
        op.f("ix_threat_indicators_created_at"), "threat_indicators", ["created_at"], unique=False
    )
    op.create_index(
        "ix_threat_indicators_value", "threat_indicators", ["canonical_value"], unique=False
    )
    op.create_table(
        "users",
        sa.Column("email", postgresql.CITEXT(), nullable=False),
        sa.Column("full_name", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("badge_number", sa.String(length=32), nullable=True),
        sa.Column("job_title", sa.String(length=96), nullable=True),
        sa.Column("department", sa.String(length=96), nullable=True),
        sa.Column("phone", sa.String(length=32), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "active",
                "invited",
                "suspended",
                "disabled",
                name="userstatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("is_superuser", sa.Boolean(), nullable=False),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("mfa_secret", sa.String(length=256), nullable=True),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("preferences", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_users_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_index(op.f("ix_users_created_at"), "users", ["created_at"], unique=False)
    op.create_table(
        "api_tokens",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=96), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_api_tokens_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_api_tokens_token_hash")),
        sa.UniqueConstraint("user_id", "name", name="uq_api_tokens_user_id_name"),
    )
    op.create_index(op.f("ix_api_tokens_created_at"), "api_tokens", ["created_at"], unique=False)
    op.create_index(op.f("ix_api_tokens_user_id"), "api_tokens", ["user_id"], unique=False)
    op.create_table(
        "backups",
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "running",
                "succeeded",
                "failed",
                "verified",
                name="backupstatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("storage_key", sa.String(length=512), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("object_count", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("custody_chain_verified", sa.Boolean(), nullable=True),
        sa.Column("audit_chain_verified", sa.Boolean(), nullable=True),
        sa.Column("restore_verified", sa.Boolean(), nullable=True),
        sa.Column("verification_note", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("triggered_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["triggered_by_id"],
            ["users.id"],
            name=op.f("fk_backups_triggered_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_backups")),
    )
    op.create_table(
        "entity_relationships",
        sa.Column("source_entity_id", sa.Uuid(), nullable=False),
        sa.Column("target_entity_id", sa.Uuid(), nullable=False),
        sa.Column("relation", sa.String(length=48), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column(
            "supporting_evidence_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_entity_id"],
            ["entities.id"],
            name=op.f("fk_entity_relationships_source_entity_id_entities"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_entity_id"],
            ["entities.id"],
            name=op.f("fk_entity_relationships_target_entity_id_entities"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_entity_relationships")),
        sa.UniqueConstraint(
            "source_entity_id",
            "target_entity_id",
            "relation",
            name="uq_entity_relationships_source_target_relation",
        ),
    )
    op.create_index(
        op.f("ix_entity_relationships_source_entity_id"),
        "entity_relationships",
        ["source_entity_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_relationships_target_entity_id"),
        "entity_relationships",
        ["target_entity_id"],
        unique=False,
    )
    op.create_table(
        "login_attempts",
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("successful", sa.Boolean(), nullable=False),
        sa.Column("failure_reason", sa.String(length=64), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_login_attempts_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_login_attempts")),
    )
    op.create_index(
        op.f("ix_login_attempts_created_at"), "login_attempts", ["created_at"], unique=False
    )
    op.create_index(
        "ix_login_attempts_email_created", "login_attempts", ["email", "created_at"], unique=False
    )
    op.create_index(
        op.f("ix_login_attempts_ip_address"), "login_attempts", ["ip_address"], unique=False
    )
    op.create_table(
        "retention_policies",
        sa.Column("name", sa.String(length=96), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("criteria", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column(
            "disposition_action",
            sa.Enum(
                "retain",
                "review",
                "archive",
                "destroy",
                name="dispositionaction",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("requires_review", sa.Boolean(), nullable=False),
        sa.Column("warn_days_before", sa.Integer(), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_retention_policies_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_retention_policies")),
        sa.UniqueConstraint("name", name=op.f("uq_retention_policies_name")),
    )
    op.create_index(
        op.f("ix_retention_policies_created_at"), "retention_policies", ["created_at"], unique=False
    )
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name=op.f("fk_role_permissions_permission_id_permissions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_permissions_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "permission_id", name=op.f("pk_role_permissions")),
    )
    op.create_table(
        "system_settings",
        sa.Column("key", sa.String(length=96), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_sensitive", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["updated_by_id"],
            ["users.id"],
            name=op.f("fk_system_settings_updated_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_system_settings")),
        sa.UniqueConstraint("key", name=op.f("uq_system_settings_key")),
    )
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["role_id"], ["roles.id"], name=op.f("fk_user_roles_role_id_roles"), ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_user_roles_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("user_id", "role_id", name=op.f("pk_user_roles")),
    )
    op.create_table(
        "user_sessions",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=96), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("device_label", sa.String(length=128), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_sessions")),
    )
    op.create_index(op.f("ix_user_sessions_user_id"), "user_sessions", ["user_id"], unique=False)
    op.create_table(
        "cases",
        sa.Column("reference", sa.String(length=24), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column(
            "incident_type",
            sa.Enum(
                "ransomware",
                "phishing",
                "business_email_compromise",
                "data_breach",
                "insider_threat",
                "financial_fraud",
                "identity_theft",
                "malware_infection",
                "denial_of_service",
                "unauthorized_access",
                "intellectual_property_theft",
                "cyber_harassment",
                "cryptocurrency_fraud",
                "supply_chain_compromise",
                "other",
                name="incidenttype",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum(
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "draft",
                "active",
                "pending_review",
                "on_hold",
                "closed",
                "archived",
                name="casestatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("incident_occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lead_investigator_id", sa.Uuid(), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("jurisdiction", sa.String(length=96), nullable=True),
        sa.Column("organization", sa.String(length=128), nullable=True),
        sa.Column("external_reference", sa.String(length=96), nullable=True),
        sa.Column("classification", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("risk_breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("risk_computed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_by_id", sa.Uuid(), nullable=True),
        sa.Column("closure_summary", sa.Text(), nullable=True),
        sa.Column("retention_policy_id", sa.Uuid(), nullable=True),
        sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("legal_hold", sa.Boolean(), nullable=False),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["closed_by_id"],
            ["users.id"],
            name=op.f("fk_cases_closed_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_cases_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["lead_investigator_id"],
            ["users.id"],
            name=op.f("fk_cases_lead_investigator_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["retention_policy_id"],
            ["retention_policies.id"],
            name=op.f("fk_cases_retention_policy_id_retention_policies"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cases")),
        sa.UniqueConstraint("reference", name=op.f("uq_cases_reference")),
    )
    op.create_index(op.f("ix_cases_created_at"), "cases", ["created_at"], unique=False)
    op.create_index(op.f("ix_cases_last_activity_at"), "cases", ["last_activity_at"], unique=False)
    op.create_index(
        op.f("ix_cases_lead_investigator_id"), "cases", ["lead_investigator_id"], unique=False
    )
    op.create_index(
        "ix_cases_reference_trgm",
        "cases",
        ["reference"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"reference": "gin_trgm_ops"},
    )
    op.create_index(op.f("ix_cases_status"), "cases", ["status"], unique=False)
    op.create_index("ix_cases_status_severity", "cases", ["status", "severity"], unique=False)
    op.create_table(
        "refresh_tokens",
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["replaced_by_id"],
            ["refresh_tokens.id"],
            name=op.f("fk_refresh_tokens_replaced_by_id_refresh_tokens"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["user_sessions.id"],
            name=op.f("fk_refresh_tokens_session_id_user_sessions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_tokens_token_hash")),
    )
    op.create_index(
        op.f("ix_refresh_tokens_session_id"), "refresh_tokens", ["session_id"], unique=False
    )
    op.create_table(
        "audit_log",
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=48), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("resource_label", sa.String(length=240), nullable=True),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_label", sa.String(length=255), nullable=False),
        sa.Column("actor_roles", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("result", sa.String(length=16), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("http_method", sa.String(length=8), nullable=True),
        sa.Column("http_path", sa.String(length=512), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("canonical_version", sa.Integer(), nullable=False),
        sa.Column("signature", sa.LargeBinary(length=64), nullable=True),
        sa.Column("signing_key_id", sa.String(length=32), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            name=op.f("fk_audit_log_actor_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_audit_log_case_id_cases"), ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
        sa.UniqueConstraint("entry_hash", name="uq_audit_log_entry_hash"),
        sa.UniqueConstraint("sequence", name="uq_audit_log_sequence"),
    )
    op.create_index(
        "ix_audit_log_action_recorded", "audit_log", ["action", "recorded_at"], unique=False
    )
    op.create_index(
        "ix_audit_log_actor_recorded", "audit_log", ["actor_id", "recorded_at"], unique=False
    )
    op.create_index(op.f("ix_audit_log_case_id"), "audit_log", ["case_id"], unique=False)
    op.create_index(op.f("ix_audit_log_ip_address"), "audit_log", ["ip_address"], unique=False)
    op.create_index(op.f("ix_audit_log_recorded_at"), "audit_log", ["recorded_at"], unique=False)
    op.create_index(
        "ix_audit_log_resource", "audit_log", ["resource_type", "resource_id"], unique=False
    )
    op.create_table(
        "case_assignments",
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_on_case", sa.String(length=48), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assigned_by_id", sa.Uuid(), nullable=True),
        sa.Column("unassigned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["assigned_by_id"],
            ["users.id"],
            name=op.f("fk_case_assignments_assigned_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_case_assignments_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_case_assignments_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_assignments")),
        sa.UniqueConstraint("case_id", "user_id", name="uq_case_assignments_case_id_user_id"),
    )
    op.create_index(
        op.f("ix_case_assignments_case_id"), "case_assignments", ["case_id"], unique=False
    )
    op.create_index(
        op.f("ix_case_assignments_user_id"), "case_assignments", ["user_id"], unique=False
    )
    op.create_table(
        "case_notes",
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("author_id", sa.Uuid(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("is_pinned", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["users.id"],
            name=op.f("fk_case_notes_author_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_notes_case_id_cases"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_notes")),
    )
    op.create_index(op.f("ix_case_notes_case_id"), "case_notes", ["case_id"], unique=False)
    op.create_index(op.f("ix_case_notes_created_at"), "case_notes", ["created_at"], unique=False)
    op.create_table(
        "case_persons",
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column(
            "role",
            sa.Enum(
                "suspect",
                "victim",
                "witness",
                "complainant",
                "person_of_interest",
                "organization",
                "custodian",
                name="casepersonrole",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("full_name", sa.String(length=160), nullable=False),
        sa.Column("aliases", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("organization", sa.String(length=160), nullable=True),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("phone", sa.String(length=48), nullable=True),
        sa.Column("address", sa.Text(), nullable=True),
        sa.Column("national_id", sa.String(length=64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("linked_entity_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_case_persons_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["linked_entity_id"],
            ["entities.id"],
            name=op.f("fk_case_persons_linked_entity_id_entities"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_persons")),
    )
    op.create_index(op.f("ix_case_persons_case_id"), "case_persons", ["case_id"], unique=False)
    op.create_index(
        op.f("ix_case_persons_created_at"), "case_persons", ["created_at"], unique=False
    )
    op.create_table(
        "case_risk_snapshots",
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("score", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column("breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("model_version", sa.String(length=16), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_case_risk_snapshots_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_risk_snapshots")),
    )
    op.create_index(
        op.f("ix_case_risk_snapshots_case_id"), "case_risk_snapshots", ["case_id"], unique=False
    )
    op.create_index(
        op.f("ix_case_risk_snapshots_created_at"),
        "case_risk_snapshots",
        ["created_at"],
        unique=False,
    )
    op.create_table(
        "case_status_history",
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column(
            "from_status",
            sa.Enum(
                "draft",
                "active",
                "pending_review",
                "on_hold",
                "closed",
                "archived",
                name="casestatus",
                native_enum=False,
                length=48,
            ),
            nullable=True,
        ),
        sa.Column(
            "to_status",
            sa.Enum(
                "draft",
                "active",
                "pending_review",
                "on_hold",
                "closed",
                "archived",
                name="casestatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("changed_by_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_case_status_history_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["changed_by_id"],
            ["users.id"],
            name=op.f("fk_case_status_history_changed_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_status_history")),
    )
    op.create_index(
        op.f("ix_case_status_history_case_id"), "case_status_history", ["case_id"], unique=False
    )
    op.create_index(
        op.f("ix_case_status_history_created_at"),
        "case_status_history",
        ["created_at"],
        unique=False,
    )
    op.create_table(
        "evidence",
        sa.Column("reference", sa.String(length=24), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("original_filename", sa.String(length=512), nullable=False),
        sa.Column(
            "evidence_type",
            sa.Enum(
                "disk_image",
                "memory_dump",
                "document",
                "spreadsheet",
                "email_message",
                "image",
                "video",
                "audio",
                "screenshot",
                "network_capture",
                "network_log",
                "system_log",
                "application_log",
                "database_export",
                "mobile_extraction",
                "chat_export",
                "cloud_export",
                "archive",
                "executable",
                "other",
                name="evidencetype",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "source_category",
            sa.Enum(
                "digital_device",
                "network_system",
                "cloud_communication",
                "external_intelligence",
                name="sourcecategory",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "acquisition_method",
            sa.Enum(
                "live_acquisition",
                "dead_disk_imaging",
                "logical_copy",
                "physical_extraction",
                "file_export",
                "network_capture",
                "log_export",
                "cloud_api_export",
                "screenshot_capture",
                "manual_collection",
                "third_party_provided",
                name="acquisitionmethod",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("source_description", sa.String(length=320), nullable=True),
        sa.Column("source_identifier", sa.String(length=160), nullable=True),
        sa.Column("source_location", sa.String(length=240), nullable=True),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acquired_by_name", sa.String(length=160), nullable=True),
        sa.Column("acquired_by_id", sa.Uuid(), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("uploaded_by_id", sa.Uuid(), nullable=True),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("mime_type", sa.String(length=160), nullable=False),
        sa.Column("declared_mime_type", sa.String(length=160), nullable=True),
        sa.Column("mime_mismatch", sa.Boolean(), nullable=False),
        sa.Column("entropy", sa.Float(), nullable=True),
        sa.Column("version_count", sa.Integer(), nullable=False),
        sa.Column("current_version_id", sa.Uuid(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "registered",
                "processing",
                "analyzed",
                "requires_attention",
                "archived",
                "disposed",
                name="evidencestatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "integrity_status",
            sa.Enum(
                "pending",
                "verified",
                "hash_mismatch",
                "decryption_failed",
                "object_missing",
                name="integritystatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("integrity_note", sa.Text(), nullable=True),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("custody_head_hash", sa.String(length=64), nullable=True),
        sa.Column("custody_event_count", sa.Integer(), nullable=False),
        sa.Column("analysis_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("extracted_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("legal_hold", sa.Boolean(), nullable=False),
        sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["acquired_by_id"],
            ["users.id"],
            name=op.f("fk_evidence_acquired_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_evidence_case_id_cases"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["current_version_id"],
            ["evidence_versions.id"],
            name=op.f("fk_evidence_current_version_id_evidence_versions"),
            ondelete="SET NULL",
            use_alter=True,
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by_id"],
            ["users.id"],
            name=op.f("fk_evidence_uploaded_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence")),
        sa.UniqueConstraint("reference", name=op.f("uq_evidence_reference")),
    )
    op.create_index(op.f("ix_evidence_case_id"), "evidence", ["case_id"], unique=False)
    op.create_index("ix_evidence_case_status", "evidence", ["case_id", "status"], unique=False)
    op.create_index(op.f("ix_evidence_created_at"), "evidence", ["created_at"], unique=False)
    op.create_index(
        "ix_evidence_filename_trgm",
        "evidence",
        ["original_filename"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"original_filename": "gin_trgm_ops"},
    )
    op.create_index(
        op.f("ix_evidence_integrity_status"), "evidence", ["integrity_status"], unique=False
    )
    op.create_index("ix_evidence_sha256", "evidence", ["sha256"], unique=False)
    op.create_index(op.f("ix_evidence_status"), "evidence", ["status"], unique=False)
    op.create_index(
        op.f("ix_evidence_uploaded_by_id"), "evidence", ["uploaded_by_id"], unique=False
    )
    op.create_table(
        "findings",
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "observation",
                "indicator_of_compromise",
                "attribution",
                "timeline_reconstruction",
                "root_cause",
                "impact_assessment",
                "recommendation",
                name="findingkind",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "confidence",
            sa.Enum(
                "low",
                "moderate",
                "high",
                "confirmed",
                name="confidence",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum(
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("author_id", sa.Uuid(), nullable=True),
        sa.Column("is_included_in_report", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["users.id"],
            name=op.f("fk_findings_author_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_findings_case_id_cases"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint("case_id", "sequence", name="uq_findings_case_id_sequence"),
    )
    op.create_index(op.f("ix_findings_case_id"), "findings", ["case_id"], unique=False)
    op.create_index(op.f("ix_findings_created_at"), "findings", ["created_at"], unique=False)
    op.create_table(
        "insights",
        sa.Column("case_id", sa.Uuid(), nullable=True),
        sa.Column(
            "kind",
            sa.Enum(
                "correlation",
                "cross_case_link",
                "anomaly",
                "temporal_pattern",
                "entity_pivot",
                "integrity",
                "risk_assessment",
                "coverage_gap",
                name="insightkind",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "provenance",
            sa.Enum(
                "derived",
                "statistical",
                "llm_assisted",
                name="insightprovenance",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum(
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("observed", sa.Text(), nullable=False),
        sa.Column("interpretation", sa.Text(), nullable=True),
        sa.Column("llm_narrative", sa.Text(), nullable=True),
        sa.Column("llm_model", sa.String(length=64), nullable=True),
        sa.Column("evidence_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("entity_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("case_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("basis", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rank_score", sa.Float(), nullable=False),
        sa.Column("generator", sa.String(length=64), nullable=False),
        sa.Column("generator_version", sa.String(length=16), nullable=False),
        sa.Column("dedupe_key", sa.String(length=128), nullable=False),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dismissed_by_id", sa.Uuid(), nullable=True),
        sa.Column("dismissed_reason", sa.Text(), nullable=True),
        sa.Column("is_pinned", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_insights_case_id_cases"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["dismissed_by_id"],
            ["users.id"],
            name=op.f("fk_insights_dismissed_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_insights")),
        sa.UniqueConstraint("case_id", "dedupe_key", name="uq_insights_case_id_dedupe_key"),
    )
    op.create_index(op.f("ix_insights_case_id"), "insights", ["case_id"], unique=False)
    op.create_index("ix_insights_case_kind", "insights", ["case_id", "kind"], unique=False)
    op.create_index(op.f("ix_insights_created_at"), "insights", ["created_at"], unique=False)
    op.create_index("ix_insights_rank", "insights", ["rank_score"], unique=False)
    op.create_table(
        "reports",
        sa.Column("reference", sa.String(length=24), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "draft",
                "pending_review",
                "approved",
                "rejected",
                "superseded",
                name="reportstatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("classification", sa.String(length=32), nullable=False),
        sa.Column("spec", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("snapshot_sha256", sa.String(length=64), nullable=True),
        sa.Column("snapshot_captured_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executive_summary", sa.Text(), nullable=True),
        sa.Column("conclusion", sa.Text(), nullable=True),
        sa.Column("distribution_list", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("prepared_by_id", sa.Uuid(), nullable=True),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by_id", sa.Uuid(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column("signature", sa.LargeBinary(length=64), nullable=True),
        sa.Column("signing_key_id", sa.String(length=32), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_by_id", sa.Uuid(), nullable=True),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("integrity_verified_count", sa.Integer(), nullable=False),
        sa.Column("integrity_failed_count", sa.Integer(), nullable=False),
        sa.Column("custody_chain_intact", sa.Boolean(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_reports_case_id_cases"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["prepared_by_id"],
            ["users.id"],
            name=op.f("fk_reports_prepared_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_id"],
            ["users.id"],
            name=op.f("fk_reports_reviewed_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["superseded_by_id"],
            ["reports.id"],
            name=op.f("fk_reports_superseded_by_id_reports"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
        sa.UniqueConstraint("case_id", "reference", name="uq_reports_case_id_reference"),
    )
    op.create_index(op.f("ix_reports_case_id"), "reports", ["case_id"], unique=False)
    op.create_index(op.f("ix_reports_created_at"), "reports", ["created_at"], unique=False)
    op.create_index("ix_reports_status", "reports", ["status"], unique=False)
    op.create_table(
        "anomalies",
        sa.Column("case_id", sa.Uuid(), nullable=True),
        sa.Column("evidence_id", sa.Uuid(), nullable=True),
        sa.Column(
            "kind",
            sa.Enum(
                "temporal_burst",
                "off_hours_activity",
                "failed_login_burst",
                "privilege_escalation",
                "mime_extension_mismatch",
                "high_entropy_content",
                "timestamp_inconsistency",
                "volume_outlier",
                "access_outside_scope",
                "email_spoofing_indicator",
                "known_malicious_indicator",
                name="anomalykind",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum(
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("method", sa.String(length=120), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=True),
        sa.Column("observed_value", sa.Float(), nullable=True),
        sa.Column("baseline_value", sa.Float(), nullable=True),
        sa.Column("deviation", sa.Float(), nullable=True),
        sa.Column("sample_size", sa.Integer(), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detector", sa.String(length=64), nullable=False),
        sa.Column("detector_version", sa.String(length=16), nullable=False),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dismissed_by_id", sa.Uuid(), nullable=True),
        sa.Column("dismissed_reason", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_anomalies_case_id_cases"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["dismissed_by_id"],
            ["users.id"],
            name=op.f("fk_anomalies_dismissed_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_anomalies_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_anomalies")),
    )
    op.create_index(op.f("ix_anomalies_case_id"), "anomalies", ["case_id"], unique=False)
    op.create_index("ix_anomalies_case_kind", "anomalies", ["case_id", "kind"], unique=False)
    op.create_index(op.f("ix_anomalies_created_at"), "anomalies", ["created_at"], unique=False)
    op.create_index(op.f("ix_anomalies_evidence_id"), "anomalies", ["evidence_id"], unique=False)
    op.create_table(
        "correlation_edges",
        sa.Column(
            "kind",
            sa.Enum(
                "shared_indicator",
                "temporal_proximity",
                "near_duplicate",
                "identical_content",
                "same_device",
                "same_account",
                "cross_case",
                name="correlationkind",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("source_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("target_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("source_case_id", sa.Uuid(), nullable=False),
        sa.Column("target_case_id", sa.Uuid(), nullable=False),
        sa.Column("is_cross_case", sa.Boolean(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("shared_entity_count", sa.Integer(), nullable=False),
        sa.Column("basis", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("computer_version", sa.String(length=16), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_case_id"],
            ["cases.id"],
            name=op.f("fk_correlation_edges_source_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_evidence_id"],
            ["evidence.id"],
            name=op.f("fk_correlation_edges_source_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_case_id"],
            ["cases.id"],
            name=op.f("fk_correlation_edges_target_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_evidence_id"],
            ["evidence.id"],
            name=op.f("fk_correlation_edges_target_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_correlation_edges")),
        sa.UniqueConstraint(
            "source_evidence_id",
            "target_evidence_id",
            "kind",
            name="uq_correlation_edges_source_target_kind",
        ),
    )
    op.create_index(
        "ix_correlation_edges_cross_case", "correlation_edges", ["is_cross_case"], unique=False
    )
    op.create_index("ix_correlation_edges_score", "correlation_edges", ["score"], unique=False)
    op.create_index(
        op.f("ix_correlation_edges_source_case_id"),
        "correlation_edges",
        ["source_case_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_edges_source_evidence_id"),
        "correlation_edges",
        ["source_evidence_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_edges_target_case_id"),
        "correlation_edges",
        ["target_case_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_correlation_edges_target_evidence_id"),
        "correlation_edges",
        ["target_evidence_id"],
        unique=False,
    )
    op.create_table(
        "custody_events",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column(
            "action",
            sa.Enum(
                "collected",
                "uploaded",
                "accessed",
                "previewed",
                "downloaded",
                "analyzed",
                "verified",
                "integrity_failed",
                "metadata_updated",
                "version_created",
                "transferred",
                "exported",
                "included_in_report",
                "archived",
                "restored",
                "legal_hold_applied",
                "legal_hold_released",
                "disposed",
                name="custodyaction",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_label", sa.String(length=255), nullable=False),
        sa.Column("actor_role", sa.String(length=48), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("new_state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("sha256_at_event", sa.String(length=64), nullable=True),
        sa.Column(
            "integrity_status_at_event",
            sa.Enum(
                "pending",
                "verified",
                "hash_mismatch",
                "decryption_failed",
                "object_missing",
                name="integritystatus",
                native_enum=False,
                length=48,
            ),
            nullable=True,
        ),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("canonical_version", sa.Integer(), nullable=False),
        sa.Column("signature", sa.LargeBinary(length=64), nullable=True),
        sa.Column("signing_key_id", sa.String(length=32), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            name=op.f("fk_custody_events_actor_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_custody_events_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_custody_events_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_custody_events")),
        sa.UniqueConstraint("entry_hash", name="uq_custody_events_entry_hash"),
        sa.UniqueConstraint(
            "evidence_id", "sequence", name="uq_custody_events_evidence_id_sequence"
        ),
    )
    op.create_index("ix_custody_events_action", "custody_events", ["action"], unique=False)
    op.create_index(op.f("ix_custody_events_case_id"), "custody_events", ["case_id"], unique=False)
    op.create_index(
        "ix_custody_events_case_recorded",
        "custody_events",
        ["case_id", "recorded_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_custody_events_evidence_id"), "custody_events", ["evidence_id"], unique=False
    )
    op.create_index(
        op.f("ix_custody_events_recorded_at"), "custody_events", ["recorded_at"], unique=False
    )
    op.create_table(
        "evidence_notes",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("author_id", sa.Uuid(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["users.id"],
            name=op.f("fk_evidence_notes_author_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_evidence_notes_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_notes")),
    )
    op.create_index(
        op.f("ix_evidence_notes_created_at"), "evidence_notes", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_evidence_notes_evidence_id"), "evidence_notes", ["evidence_id"], unique=False
    )
    op.create_table(
        "evidence_tags",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("tag_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_evidence_tags_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tag_id"], ["tags.id"], name=op.f("fk_evidence_tags_tag_id_tags"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("evidence_id", "tag_id", name=op.f("pk_evidence_tags")),
    )
    op.create_table(
        "evidence_versions",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("stored_object_id", sa.Uuid(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("sha1", sa.String(length=40), nullable=True),
        sa.Column("md5", sa.String(length=32), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("mime_type", sa.String(length=160), nullable=False),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.String(length=240), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_evidence_versions_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_evidence_versions_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["stored_object_id"],
            ["stored_objects.id"],
            name=op.f("fk_evidence_versions_stored_object_id_stored_objects"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_versions")),
        sa.UniqueConstraint(
            "evidence_id", "version_number", name="uq_evidence_versions_evidence_id_version_number"
        ),
    )
    op.create_index(
        op.f("ix_evidence_versions_created_at"), "evidence_versions", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_evidence_versions_evidence_id"), "evidence_versions", ["evidence_id"], unique=False
    )
    op.create_table(
        "finding_evidence",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_finding_evidence_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_evidence_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("finding_id", "evidence_id", name=op.f("pk_finding_evidence")),
    )
    op.create_table(
        "indicator_matches",
        sa.Column("indicator_id", sa.Uuid(), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("context", sa.String(length=240), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_indicator_matches_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["entity_id"],
            ["entities.id"],
            name=op.f("fk_indicator_matches_entity_id_entities"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_indicator_matches_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["threat_indicators.id"],
            name=op.f("fk_indicator_matches_indicator_id_threat_indicators"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_indicator_matches")),
        sa.UniqueConstraint(
            "indicator_id", "evidence_id", name="uq_indicator_matches_indicator_id_evidence_id"
        ),
    )
    op.create_index("ix_indicator_matches_case", "indicator_matches", ["case_id"], unique=False)
    op.create_index(
        op.f("ix_indicator_matches_created_at"), "indicator_matches", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_indicator_matches_entity_id"), "indicator_matches", ["entity_id"], unique=False
    )
    op.create_index(
        op.f("ix_indicator_matches_evidence_id"), "indicator_matches", ["evidence_id"], unique=False
    )
    op.create_index(
        op.f("ix_indicator_matches_indicator_id"),
        "indicator_matches",
        ["indicator_id"],
        unique=False,
    )
    op.create_table(
        "jobs",
        sa.Column("task", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "running",
                "succeeded",
                "failed",
                "dead",
                "cancelled",
                name="jobstatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("locked_by", sa.String(length=64), nullable=True),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("dedupe_key", sa.String(length=160), nullable=True),
        sa.Column("case_id", sa.Uuid(), nullable=True),
        sa.Column("evidence_id", sa.Uuid(), nullable=True),
        sa.Column("requested_by_id", sa.Uuid(), nullable=True),
        sa.Column("parent_job_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_jobs_case_id_cases"), ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_jobs_evidence_id_evidence"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["parent_job_id"],
            ["jobs.id"],
            name=op.f("fk_jobs_parent_job_id_jobs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"],
            ["users.id"],
            name=op.f("fk_jobs_requested_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
    )
    op.create_index(op.f("ix_jobs_case_id"), "jobs", ["case_id"], unique=False)
    op.create_index("ix_jobs_claim", "jobs", ["status", "priority", "run_at"], unique=False)
    op.create_index(op.f("ix_jobs_created_at"), "jobs", ["created_at"], unique=False)
    op.create_index(op.f("ix_jobs_evidence_id"), "jobs", ["evidence_id"], unique=False)
    op.create_index(op.f("ix_jobs_status"), "jobs", ["status"], unique=False)
    op.create_index("ix_jobs_task_status", "jobs", ["task", "status"], unique=False)
    op.create_index(
        "uq_jobs_active_dedupe_key",
        "jobs",
        ["dedupe_key"],
        unique=True,
        postgresql_where=sa.text("status in ('queued', 'running') and dedupe_key is not null"),
    )
    op.create_table(
        "legal_holds",
        sa.Column("reference", sa.String(length=64), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=True),
        sa.Column("evidence_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("authority", sa.String(length=160), nullable=True),
        sa.Column("applied_by_id", sa.Uuid(), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_by_id", sa.Uuid(), nullable=True),
        sa.Column("release_reason", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["applied_by_id"],
            ["users.id"],
            name=op.f("fk_legal_holds_applied_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_legal_holds_case_id_cases"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_legal_holds_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["released_by_id"],
            ["users.id"],
            name=op.f("fk_legal_holds_released_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_legal_holds")),
    )
    op.create_index(op.f("ix_legal_holds_case_id"), "legal_holds", ["case_id"], unique=False)
    op.create_index(op.f("ix_legal_holds_created_at"), "legal_holds", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_legal_holds_evidence_id"), "legal_holds", ["evidence_id"], unique=False
    )
    op.create_table(
        "report_artifacts",
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column(
            "format",
            sa.Enum(
                "pdf", "html", "json", "csv", name="reportformat", native_enum=False, length=48
            ),
            nullable=False,
        ),
        sa.Column("filename", sa.String(length=240), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("stored_object_id", sa.Uuid(), nullable=False),
        sa.Column("page_count", sa.Integer(), nullable=True),
        sa.Column("render_duration_ms", sa.Integer(), nullable=True),
        sa.Column("generated_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["generated_by_id"],
            ["users.id"],
            name=op.f("fk_report_artifacts_generated_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["reports.id"],
            name=op.f("fk_report_artifacts_report_id_reports"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["stored_object_id"],
            ["stored_objects.id"],
            name=op.f("fk_report_artifacts_stored_object_id_stored_objects"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_artifacts")),
        sa.UniqueConstraint("report_id", "format", name="uq_report_artifacts_report_id_format"),
    )
    op.create_index(
        op.f("ix_report_artifacts_created_at"), "report_artifacts", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_report_artifacts_report_id"), "report_artifacts", ["report_id"], unique=False
    )
    op.create_table(
        "alerts",
        sa.Column("reference", sa.String(length=24), nullable=False),
        sa.Column(
            "type",
            sa.Enum(
                "integrity_failure",
                "chain_verification_failure",
                "unauthorized_access_attempt",
                "access_outside_scope",
                "suspicious_download_volume",
                "ai_anomaly_detected",
                "malicious_indicator_match",
                "evidence_pending_analysis",
                "case_requires_attention",
                "retention_expiry_approaching",
                "backup_failure",
                "job_failure",
                "account_locked",
                name="alerttype",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "source",
            sa.Enum(
                "integrity_verifier",
                "anomaly_detector",
                "security_monitor",
                "threat_intelligence",
                "retention_engine",
                "platform_monitor",
                name="alertsource",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum(
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "open",
                "acknowledged",
                "resolved",
                "suppressed",
                name="alertstatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("recommended_action", sa.Text(), nullable=True),
        sa.Column("dedupe_key", sa.String(length=160), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=True),
        sa.Column("evidence_id", sa.Uuid(), nullable=True),
        sa.Column("anomaly_id", sa.Uuid(), nullable=True),
        sa.Column("subject_user_id", sa.Uuid(), nullable=True),
        sa.Column("assigned_to_id", sa.Uuid(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by_id", sa.Uuid(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by_id", sa.Uuid(), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["acknowledged_by_id"],
            ["users.id"],
            name=op.f("fk_alerts_acknowledged_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["anomaly_id"],
            ["anomalies.id"],
            name=op.f("fk_alerts_anomaly_id_anomalies"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to_id"],
            ["users.id"],
            name=op.f("fk_alerts_assigned_to_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_alerts_case_id_cases"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_alerts_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["resolved_by_id"],
            ["users.id"],
            name=op.f("fk_alerts_resolved_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["subject_user_id"],
            ["users.id"],
            name=op.f("fk_alerts_subject_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
        sa.UniqueConstraint("reference", name=op.f("uq_alerts_reference")),
    )
    op.create_index(op.f("ix_alerts_assigned_to_id"), "alerts", ["assigned_to_id"], unique=False)
    op.create_index(op.f("ix_alerts_case_id"), "alerts", ["case_id"], unique=False)
    op.create_index(op.f("ix_alerts_created_at"), "alerts", ["created_at"], unique=False)
    op.create_index(op.f("ix_alerts_evidence_id"), "alerts", ["evidence_id"], unique=False)
    op.create_index(op.f("ix_alerts_status"), "alerts", ["status"], unique=False)
    op.create_index("ix_alerts_status_severity", "alerts", ["status", "severity"], unique=False)
    op.create_index("ix_alerts_type_created", "alerts", ["type", "created_at"], unique=False)
    op.create_index(
        "uq_alerts_open_dedupe_key",
        "alerts",
        ["dedupe_key"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
    )
    op.create_table(
        "analysis_runs",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_version_id", sa.Uuid(), nullable=True),
        sa.Column("analyzer", sa.String(length=64), nullable=False),
        sa.Column("analyzer_version", sa.String(length=16), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "running",
                "completed",
                "failed",
                "skipped",
                name="analysisstatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("bytes_examined", sa.BigInteger(), nullable=True),
        sa.Column("entity_count", sa.Integer(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("skip_reason", sa.String(length=240), nullable=True),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("requested_by_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_analysis_runs_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_analysis_runs_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_version_id"],
            ["evidence_versions.id"],
            name=op.f("fk_analysis_runs_evidence_version_id_evidence_versions"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"],
            ["users.id"],
            name=op.f("fk_analysis_runs_requested_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_analysis_runs")),
    )
    op.create_index(op.f("ix_analysis_runs_case_id"), "analysis_runs", ["case_id"], unique=False)
    op.create_index(
        "ix_analysis_runs_evidence_analyzer",
        "analysis_runs",
        ["evidence_id", "analyzer"],
        unique=False,
    )
    op.create_index(
        op.f("ix_analysis_runs_evidence_id"), "analysis_runs", ["evidence_id"], unique=False
    )
    op.create_table(
        "integrity_checks",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_version_id", sa.Uuid(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "verified",
                "hash_mismatch",
                "decryption_failed",
                "object_missing",
                name="integritystatus",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("expected_sha256", sa.String(length=64), nullable=False),
        sa.Column("computed_sha256", sa.String(length=64), nullable=True),
        sa.Column("ciphertext_verified", sa.Boolean(), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=False),
        sa.Column("checked_by_id", sa.Uuid(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["checked_by_id"],
            ["users.id"],
            name=op.f("fk_integrity_checks_checked_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_integrity_checks_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_version_id"],
            ["evidence_versions.id"],
            name=op.f("fk_integrity_checks_evidence_version_id_evidence_versions"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integrity_checks")),
    )
    op.create_index(
        op.f("ix_integrity_checks_created_at"), "integrity_checks", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_integrity_checks_evidence_id"), "integrity_checks", ["evidence_id"], unique=False
    )
    op.create_table(
        "alert_events",
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_label", sa.String(length=255), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "from_status",
            sa.Enum(
                "open",
                "acknowledged",
                "resolved",
                "suppressed",
                name="alertstatus",
                native_enum=False,
                length=48,
            ),
            nullable=True,
        ),
        sa.Column(
            "to_status",
            sa.Enum(
                "open",
                "acknowledged",
                "resolved",
                "suppressed",
                name="alertstatus",
                native_enum=False,
                length=48,
            ),
            nullable=True,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            name=op.f("fk_alert_events_actor_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_alert_events_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_events")),
    )
    op.create_index(op.f("ix_alert_events_alert_id"), "alert_events", ["alert_id"], unique=False)
    op.create_index(
        op.f("ix_alert_events_created_at"), "alert_events", ["created_at"], unique=False
    )
    op.create_table(
        "analysis_findings",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=True),
        sa.Column("code", sa.String(length=96), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("analyzer", sa.String(length=64), nullable=False),
        sa.Column("analyzer_version", sa.String(length=16), nullable=False),
        sa.Column("locator", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("excerpt", sa.Text(), nullable=True),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["analysis_run_id"],
            ["analysis_runs.id"],
            name=op.f("fk_analysis_findings_analysis_run_id_analysis_runs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_analysis_findings_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_analysis_findings_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_analysis_findings")),
    )
    op.create_index(
        "ix_analysis_findings_case_code", "analysis_findings", ["case_id", "code"], unique=False
    )
    op.create_index(
        op.f("ix_analysis_findings_created_at"), "analysis_findings", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_analysis_findings_evidence_id"), "analysis_findings", ["evidence_id"], unique=False
    )
    op.create_table(
        "entity_occurrences",
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=True),
        sa.Column("analyzer", sa.String(length=64), nullable=False),
        sa.Column("analyzer_version", sa.String(length=16), nullable=False),
        sa.Column("locator", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("excerpt", sa.Text(), nullable=True),
        sa.Column("context", sa.String(length=160), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["analysis_run_id"],
            ["analysis_runs.id"],
            name=op.f("fk_entity_occurrences_analysis_run_id_analysis_runs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_entity_occurrences_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["entity_id"],
            ["entities.id"],
            name=op.f("fk_entity_occurrences_entity_id_entities"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_entity_occurrences_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_entity_occurrences")),
    )
    op.create_index("ix_entity_occurrences_case", "entity_occurrences", ["case_id"], unique=False)
    op.create_index(
        op.f("ix_entity_occurrences_created_at"), "entity_occurrences", ["created_at"], unique=False
    )
    op.create_index(
        "ix_entity_occurrences_entity_evidence",
        "entity_occurrences",
        ["entity_id", "evidence_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_occurrences_entity_id"), "entity_occurrences", ["entity_id"], unique=False
    )
    op.create_index(
        op.f("ix_entity_occurrences_evidence_id"),
        "entity_occurrences",
        ["evidence_id"],
        unique=False,
    )
    op.create_table(
        "notifications",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=48), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            sa.Enum(
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("link", sa.String(length=512), nullable=True),
        sa.Column("alert_id", sa.Uuid(), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_dismissed", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_notifications_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_notifications_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notifications")),
    )
    op.create_index(
        op.f("ix_notifications_created_at"), "notifications", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_notifications_user_id"), "notifications", ["user_id"], unique=False)
    op.create_index(
        "ix_notifications_user_read", "notifications", ["user_id", "read_at"], unique=False
    )
    op.create_table(
        "observations",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=True),
        sa.Column(
            "kind",
            sa.Enum(
                "login_success",
                "login_failure",
                "account_lockout",
                "privilege_change",
                "file_access",
                "file_created",
                "file_modified",
                "file_deleted",
                "process_execution",
                "network_connection",
                "dns_query",
                "http_request",
                "email_sent",
                "email_received",
                "email_relay_hop",
                "media_captured",
                "document_authored",
                "transaction",
                "configuration_change",
                "generic",
                name="observationkind",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "time_confidence",
            sa.Enum(
                "low",
                "moderate",
                "high",
                "confirmed",
                name="confidence",
                native_enum=False,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("timezone_assumed", sa.Boolean(), nullable=False),
        sa.Column("summary", sa.String(length=400), nullable=False),
        sa.Column("actor_value", sa.String(length=255), nullable=True),
        sa.Column("source_value", sa.String(length=255), nullable=True),
        sa.Column("target_value", sa.String(length=255), nullable=True),
        sa.Column("outcome", sa.String(length=48), nullable=True),
        sa.Column("analyzer", sa.String(length=64), nullable=False),
        sa.Column("analyzer_version", sa.String(length=16), nullable=False),
        sa.Column("locator", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("excerpt", sa.Text(), nullable=True),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["analysis_run_id"],
            ["analysis_runs.id"],
            name=op.f("fk_observations_analysis_run_id_analysis_runs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_observations_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_observations_evidence_id_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_observations")),
    )
    op.create_index(
        "ix_observations_case_occurred", "observations", ["case_id", "occurred_at"], unique=False
    )
    op.create_index(
        op.f("ix_observations_created_at"), "observations", ["created_at"], unique=False
    )
    op.create_index(
        "ix_observations_evidence_occurred",
        "observations",
        ["evidence_id", "occurred_at"],
        unique=False,
    )
    op.create_index("ix_observations_kind", "observations", ["kind"], unique=False)
    op.create_table(
        "observation_entities",
        sa.Column("observation_id", sa.Uuid(), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=32), server_default="involved", nullable=False),
        sa.ForeignKeyConstraint(
            ["entity_id"],
            ["entities.id"],
            name=op.f("fk_observation_entities_entity_id_entities"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["observation_id"],
            ["observations.id"],
            name=op.f("fk_observation_entities_observation_id_observations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "observation_id", "entity_id", name=op.f("pk_observation_entities")
        ),
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("observation_entities")
    op.drop_index("ix_observations_kind", table_name="observations")
    op.drop_index("ix_observations_evidence_occurred", table_name="observations")
    op.drop_index(op.f("ix_observations_created_at"), table_name="observations")
    op.drop_index("ix_observations_case_occurred", table_name="observations")
    op.drop_table("observations")
    op.drop_index("ix_notifications_user_read", table_name="notifications")
    op.drop_index(op.f("ix_notifications_user_id"), table_name="notifications")
    op.drop_index(op.f("ix_notifications_created_at"), table_name="notifications")
    op.drop_table("notifications")
    op.drop_index(op.f("ix_entity_occurrences_evidence_id"), table_name="entity_occurrences")
    op.drop_index(op.f("ix_entity_occurrences_entity_id"), table_name="entity_occurrences")
    op.drop_index("ix_entity_occurrences_entity_evidence", table_name="entity_occurrences")
    op.drop_index(op.f("ix_entity_occurrences_created_at"), table_name="entity_occurrences")
    op.drop_index("ix_entity_occurrences_case", table_name="entity_occurrences")
    op.drop_table("entity_occurrences")
    op.drop_index(op.f("ix_analysis_findings_evidence_id"), table_name="analysis_findings")
    op.drop_index(op.f("ix_analysis_findings_created_at"), table_name="analysis_findings")
    op.drop_index("ix_analysis_findings_case_code", table_name="analysis_findings")
    op.drop_table("analysis_findings")
    op.drop_index(op.f("ix_alert_events_created_at"), table_name="alert_events")
    op.drop_index(op.f("ix_alert_events_alert_id"), table_name="alert_events")
    op.drop_table("alert_events")
    op.drop_index(op.f("ix_integrity_checks_evidence_id"), table_name="integrity_checks")
    op.drop_index(op.f("ix_integrity_checks_created_at"), table_name="integrity_checks")
    op.drop_table("integrity_checks")
    op.drop_index(op.f("ix_analysis_runs_evidence_id"), table_name="analysis_runs")
    op.drop_index("ix_analysis_runs_evidence_analyzer", table_name="analysis_runs")
    op.drop_index(op.f("ix_analysis_runs_case_id"), table_name="analysis_runs")
    op.drop_table("analysis_runs")
    op.drop_index(
        "uq_alerts_open_dedupe_key",
        table_name="alerts",
        postgresql_where=sa.text("status = 'open'"),
    )
    op.drop_index("ix_alerts_type_created", table_name="alerts")
    op.drop_index("ix_alerts_status_severity", table_name="alerts")
    op.drop_index(op.f("ix_alerts_status"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_evidence_id"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_created_at"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_case_id"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_assigned_to_id"), table_name="alerts")
    op.drop_table("alerts")
    op.drop_index(op.f("ix_report_artifacts_report_id"), table_name="report_artifacts")
    op.drop_index(op.f("ix_report_artifacts_created_at"), table_name="report_artifacts")
    op.drop_table("report_artifacts")
    op.drop_index(op.f("ix_legal_holds_evidence_id"), table_name="legal_holds")
    op.drop_index(op.f("ix_legal_holds_created_at"), table_name="legal_holds")
    op.drop_index(op.f("ix_legal_holds_case_id"), table_name="legal_holds")
    op.drop_table("legal_holds")
    op.drop_index(
        "uq_jobs_active_dedupe_key",
        table_name="jobs",
        postgresql_where=sa.text("status in ('queued', 'running') and dedupe_key is not null"),
    )
    op.drop_index("ix_jobs_task_status", table_name="jobs")
    op.drop_index(op.f("ix_jobs_status"), table_name="jobs")
    op.drop_index(op.f("ix_jobs_evidence_id"), table_name="jobs")
    op.drop_index(op.f("ix_jobs_created_at"), table_name="jobs")
    op.drop_index("ix_jobs_claim", table_name="jobs")
    op.drop_index(op.f("ix_jobs_case_id"), table_name="jobs")
    op.drop_table("jobs")
    op.drop_index(op.f("ix_indicator_matches_indicator_id"), table_name="indicator_matches")
    op.drop_index(op.f("ix_indicator_matches_evidence_id"), table_name="indicator_matches")
    op.drop_index(op.f("ix_indicator_matches_entity_id"), table_name="indicator_matches")
    op.drop_index(op.f("ix_indicator_matches_created_at"), table_name="indicator_matches")
    op.drop_index("ix_indicator_matches_case", table_name="indicator_matches")
    op.drop_table("indicator_matches")
    op.drop_table("finding_evidence")
    op.drop_index(op.f("ix_evidence_versions_evidence_id"), table_name="evidence_versions")
    op.drop_index(op.f("ix_evidence_versions_created_at"), table_name="evidence_versions")
    op.drop_table("evidence_versions")
    op.drop_table("evidence_tags")
    op.drop_index(op.f("ix_evidence_notes_evidence_id"), table_name="evidence_notes")
    op.drop_index(op.f("ix_evidence_notes_created_at"), table_name="evidence_notes")
    op.drop_table("evidence_notes")
    op.drop_index(op.f("ix_custody_events_recorded_at"), table_name="custody_events")
    op.drop_index(op.f("ix_custody_events_evidence_id"), table_name="custody_events")
    op.drop_index("ix_custody_events_case_recorded", table_name="custody_events")
    op.drop_index(op.f("ix_custody_events_case_id"), table_name="custody_events")
    op.drop_index("ix_custody_events_action", table_name="custody_events")
    op.drop_table("custody_events")
    op.drop_index(op.f("ix_correlation_edges_target_evidence_id"), table_name="correlation_edges")
    op.drop_index(op.f("ix_correlation_edges_target_case_id"), table_name="correlation_edges")
    op.drop_index(op.f("ix_correlation_edges_source_evidence_id"), table_name="correlation_edges")
    op.drop_index(op.f("ix_correlation_edges_source_case_id"), table_name="correlation_edges")
    op.drop_index("ix_correlation_edges_score", table_name="correlation_edges")
    op.drop_index("ix_correlation_edges_cross_case", table_name="correlation_edges")
    op.drop_table("correlation_edges")
    op.drop_index(op.f("ix_anomalies_evidence_id"), table_name="anomalies")
    op.drop_index(op.f("ix_anomalies_created_at"), table_name="anomalies")
    op.drop_index("ix_anomalies_case_kind", table_name="anomalies")
    op.drop_index(op.f("ix_anomalies_case_id"), table_name="anomalies")
    op.drop_table("anomalies")
    op.drop_index("ix_reports_status", table_name="reports")
    op.drop_index(op.f("ix_reports_created_at"), table_name="reports")
    op.drop_index(op.f("ix_reports_case_id"), table_name="reports")
    op.drop_table("reports")
    op.drop_index("ix_insights_rank", table_name="insights")
    op.drop_index(op.f("ix_insights_created_at"), table_name="insights")
    op.drop_index("ix_insights_case_kind", table_name="insights")
    op.drop_index(op.f("ix_insights_case_id"), table_name="insights")
    op.drop_table("insights")
    op.drop_index(op.f("ix_findings_created_at"), table_name="findings")
    op.drop_index(op.f("ix_findings_case_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_evidence_uploaded_by_id"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_status"), table_name="evidence")
    op.drop_index("ix_evidence_sha256", table_name="evidence")
    op.drop_index(op.f("ix_evidence_integrity_status"), table_name="evidence")
    op.drop_index(
        "ix_evidence_filename_trgm",
        table_name="evidence",
        postgresql_using="gin",
        postgresql_ops={"original_filename": "gin_trgm_ops"},
    )
    op.drop_index(op.f("ix_evidence_created_at"), table_name="evidence")
    op.drop_index("ix_evidence_case_status", table_name="evidence")
    op.drop_index(op.f("ix_evidence_case_id"), table_name="evidence")
    op.drop_table("evidence")
    op.drop_index(op.f("ix_case_status_history_created_at"), table_name="case_status_history")
    op.drop_index(op.f("ix_case_status_history_case_id"), table_name="case_status_history")
    op.drop_table("case_status_history")
    op.drop_index(op.f("ix_case_risk_snapshots_created_at"), table_name="case_risk_snapshots")
    op.drop_index(op.f("ix_case_risk_snapshots_case_id"), table_name="case_risk_snapshots")
    op.drop_table("case_risk_snapshots")
    op.drop_index(op.f("ix_case_persons_created_at"), table_name="case_persons")
    op.drop_index(op.f("ix_case_persons_case_id"), table_name="case_persons")
    op.drop_table("case_persons")
    op.drop_index(op.f("ix_case_notes_created_at"), table_name="case_notes")
    op.drop_index(op.f("ix_case_notes_case_id"), table_name="case_notes")
    op.drop_table("case_notes")
    op.drop_index(op.f("ix_case_assignments_user_id"), table_name="case_assignments")
    op.drop_index(op.f("ix_case_assignments_case_id"), table_name="case_assignments")
    op.drop_table("case_assignments")
    op.drop_index("ix_audit_log_resource", table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_recorded_at"), table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_ip_address"), table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_case_id"), table_name="audit_log")
    op.drop_index("ix_audit_log_actor_recorded", table_name="audit_log")
    op.drop_index("ix_audit_log_action_recorded", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index(op.f("ix_refresh_tokens_session_id"), table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_index("ix_cases_status_severity", table_name="cases")
    op.drop_index(op.f("ix_cases_status"), table_name="cases")
    op.drop_index(
        "ix_cases_reference_trgm",
        table_name="cases",
        postgresql_using="gin",
        postgresql_ops={"reference": "gin_trgm_ops"},
    )
    op.drop_index(op.f("ix_cases_lead_investigator_id"), table_name="cases")
    op.drop_index(op.f("ix_cases_last_activity_at"), table_name="cases")
    op.drop_index(op.f("ix_cases_created_at"), table_name="cases")
    op.drop_table("cases")
    op.drop_index(op.f("ix_user_sessions_user_id"), table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_table("user_roles")
    op.drop_table("system_settings")
    op.drop_table("role_permissions")
    op.drop_index(op.f("ix_retention_policies_created_at"), table_name="retention_policies")
    op.drop_table("retention_policies")
    op.drop_index(op.f("ix_login_attempts_ip_address"), table_name="login_attempts")
    op.drop_index("ix_login_attempts_email_created", table_name="login_attempts")
    op.drop_index(op.f("ix_login_attempts_created_at"), table_name="login_attempts")
    op.drop_table("login_attempts")
    op.drop_index(
        op.f("ix_entity_relationships_target_entity_id"), table_name="entity_relationships"
    )
    op.drop_index(
        op.f("ix_entity_relationships_source_entity_id"), table_name="entity_relationships"
    )
    op.drop_table("entity_relationships")
    op.drop_table("backups")
    op.drop_index(op.f("ix_api_tokens_user_id"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_created_at"), table_name="api_tokens")
    op.drop_table("api_tokens")
    op.drop_index(op.f("ix_users_created_at"), table_name="users")
    op.drop_table("users")
    op.drop_index("ix_threat_indicators_value", table_name="threat_indicators")
    op.drop_index(op.f("ix_threat_indicators_created_at"), table_name="threat_indicators")
    op.drop_table("threat_indicators")
    op.drop_index(op.f("ix_tags_created_at"), table_name="tags")
    op.drop_table("tags")
    op.drop_index(op.f("ix_system_health_samples_created_at"), table_name="system_health_samples")
    op.drop_table("system_health_samples")
    op.drop_index(op.f("ix_stored_objects_created_at"), table_name="stored_objects")
    op.drop_table("stored_objects")
    op.drop_index(op.f("ix_roles_created_at"), table_name="roles")
    op.drop_table("roles")
    op.drop_table("permissions")
    op.drop_index(op.f("ix_periodic_tasks_next_run_at"), table_name="periodic_tasks")
    op.drop_index(op.f("ix_periodic_tasks_created_at"), table_name="periodic_tasks")
    op.drop_table("periodic_tasks")
    op.drop_index(
        "ix_entities_value_trgm",
        table_name="entities",
        postgresql_using="gin",
        postgresql_ops={"canonical_value": "gin_trgm_ops"},
    )
    op.drop_index(op.f("ix_entities_type"), table_name="entities")
    op.drop_index(op.f("ix_entities_created_at"), table_name="entities")
    op.drop_table("entities")
    # ### end Alembic commands ###
