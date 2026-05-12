"""audit_events table + RLS for F.6 Audit Agent (F.6 Task 3)

Revision ID: 0003_audit_events
Revises: 0002_memory_rls
Create Date: 2026-05-12

Materializes the `audit_events` table the F.6 `AuditStore` writes into.
Mirrors F.5's `0001_memory_baseline` shape: dialect-portable column
types via `charter.memory.models._Portable*`; the Postgres-only
`jsonb_path_ops` GIN index gates behind `dialect.name == 'postgresql'`.

This migration is also where the Audit Agent's tenant-isolation policy
lands. Same pattern as `0002_memory_rls`: `ENABLE ROW LEVEL SECURITY`
+ `tenant_isolation` policy reading `current_setting('app.tenant_id',
true)`. Postgres-only — aiosqlite skips the RLS block cleanly.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# The migration reuses the dialect-portable TypeDecorator already shipped
# in charter.memory.models — single source of truth.
from charter.memory.models import _PortableJSONB

revision: str = "0003_audit_events"
down_revision: str | None = "0002_memory_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column(
            "audit_event_id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("tenant_id", sa.String(length=26), nullable=False),
        sa.Column("correlation_id", sa.String(length=32), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("payload", _PortableJSONB(), nullable=False),
        sa.Column("previous_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("entry_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("emitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "entry_hash",
            name="uq_audit_events_tenant_entry_hash",
        ),
    )
    op.create_index(
        "ix_audit_events_tenant_emitted",
        "audit_events",
        ["tenant_id", "emitted_at"],
    )
    op.create_index(
        "ix_audit_events_tenant_action",
        "audit_events",
        ["tenant_id", "action"],
    )
    op.create_index(
        "ix_audit_events_correlation",
        "audit_events",
        ["correlation_id"],
    )

    if _is_postgres():
        # GIN index over JSONB payload — backs `payload->>'severity' = 'high'`
        # and similar queries from the operator console.
        op.execute(
            "CREATE INDEX ix_audit_events_payload_gin "
            "ON audit_events USING GIN (payload jsonb_path_ops)"
        )

        # Row-Level Security mirrors `0002_memory_rls` — same policy name
        # convention (`tenant_isolation`), same session variable.
        op.execute("ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY tenant_isolation ON audit_events "
            "USING (tenant_id = current_setting('app.tenant_id', true))"
        )


def downgrade() -> None:
    if _is_postgres():
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON audit_events")
        op.execute("ALTER TABLE audit_events DISABLE ROW LEVEL SECURITY")
        op.execute("DROP INDEX IF EXISTS ix_audit_events_payload_gin")

    op.drop_index("ix_audit_events_correlation", table_name="audit_events")
    op.drop_index("ix_audit_events_tenant_action", table_name="audit_events")
    op.drop_index("ix_audit_events_tenant_emitted", table_name="audit_events")
    op.drop_table("audit_events")
