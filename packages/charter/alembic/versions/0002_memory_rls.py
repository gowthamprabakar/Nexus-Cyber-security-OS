"""memory engines — per-tenant row-level security policies (F.5 Task 7)

Revision ID: 0002_memory_rls
Revises: 0001_memory_baseline
Create Date: 2026-05-12

Adds Postgres Row-Level Security on every memory table:

    ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON <table>
        USING (tenant_id = current_setting('app.tenant_id', true));

The `MemoryService` facade (F.5 Task 9) sets `app.tenant_id` per
session inside a `SET LOCAL` so the variable scope matches the txn
lifetime. Application-side `WHERE tenant_id = ?` filters stay as the
secondary defence.

RLS is Postgres-only — both `upgrade()` and `downgrade()` are gated
by `dialect.name == 'postgresql'`. On aiosqlite the migration is a
no-op (the four tables already exist from `0001_memory_baseline`;
nothing to do here).

The live "off-tenant queries return empty" assertion lives in F.5
Task 10's Postgres integration test (RLS can't be exercised against
sqlite). What this migration's *structural* tests verify is that the
DDL strings are present and the gating is correct.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_memory_rls"
down_revision: str | None = "0001_memory_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if not _is_postgres():
        # RLS is a Postgres feature. aiosqlite unit tests skip cleanly.
        return

    op.execute("ALTER TABLE episodes ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON episodes "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )

    op.execute("ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON playbooks "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )

    op.execute("ALTER TABLE entities ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON entities "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )

    op.execute("ALTER TABLE relationships ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON relationships "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )


def downgrade() -> None:
    if not _is_postgres():
        return

    op.execute("DROP POLICY IF EXISTS tenant_isolation ON relationships")
    op.execute("ALTER TABLE relationships DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS tenant_isolation ON entities")
    op.execute("ALTER TABLE entities DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS tenant_isolation ON playbooks")
    op.execute("ALTER TABLE playbooks DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS tenant_isolation ON episodes")
    op.execute("ALTER TABLE episodes DISABLE ROW LEVEL SECURITY")
