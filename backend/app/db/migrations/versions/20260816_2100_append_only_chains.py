"""Enforce append-only semantics on the custody and audit hash chains.

Application code is careful never to update or delete these rows, but "careful code" is not
a control an auditor can verify. This migration makes the guarantee structural: PostgreSQL
itself rejects ``UPDATE``, ``DELETE`` and ``TRUNCATE`` on ``custody_events`` and
``audit_log``, so an insider with a database connection and an ordinary application role
cannot quietly rewrite history.

``UPDATE`` is refused unconditionally. ``DELETE`` is refused unless the transaction has
explicitly opted in by setting ``cybertrace.allow_chain_purge = 'on'``, which exists for two
legitimate needs - court-ordered destruction under a retention policy, and test teardown.
Requiring the flag inside the transaction means a purge is always a deliberate, visible act
rather than an accident, and the surrounding service still records why it happened.

Revision ID: 8c1d4b7e2a90
Revises: f2f3a5af0d8f
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "8c1d4b7e2a90"
down_revision: str | None = "f2f3a5af0d8f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPEND_ONLY_TABLES = ("custody_events", "audit_log")

GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION cybertrace_append_only_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND coalesce(current_setting('cybertrace.allow_chain_purge', true), 'off') = 'on' THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION
        '% on %.% is not permitted: this table is an append-only hash chain',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation',
              HINT = 'History is tamper-evident by design. A retention disposal must set '
                     'cybertrace.allow_chain_purge and record its justification.';
END;
$$;
"""

TRUNCATE_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION cybertrace_no_truncate_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'TRUNCATE on %.% is not permitted: append-only hash chain',
        TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
END;
$$;
"""


def upgrade() -> None:
    # Idempotent so a database provisioned without the initdb scripts still works.
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

    op.execute(GUARD_FUNCTION)
    op.execute(TRUNCATE_GUARD_FUNCTION)

    for table in APPEND_ONLY_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION cybertrace_append_only_guard()
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_no_truncate
            BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION cybertrace_no_truncate_guard()
            """
        )


def downgrade() -> None:
    for table in APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_append_only ON {table}")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_no_truncate ON {table}")
    op.execute("DROP FUNCTION IF EXISTS cybertrace_append_only_guard()")
    op.execute("DROP FUNCTION IF EXISTS cybertrace_no_truncate_guard()")
