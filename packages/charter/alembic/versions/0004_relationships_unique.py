"""cross-run edge dedup — UNIQUE index on relationships (ADR-022, Stage 3)

Revision ID: 0004_relationships_unique
Revises: 0003_audit_events
Create Date: 2026-06-18

`SemanticStore.add_relationship` was INSERT-only and `relationships` carried no
UNIQUE constraint, so every run re-inserted the same edges → duplicate `AFFECTS`
(and every other) edge accumulation across runs. `KnowledgeGraphWriterBase`
deduped only *within* a run (a per-instance set). This migration adds the DB-level
cross-run backstop the base's own docstring always named.

Two steps:

1. **Back-dedup existing rows.** Delete duplicate
   `(tenant_id, src_entity_id, dst_entity_id, relationship_type)` groups, keeping the
   lowest `relationship_id` (the first-written edge — matches the within-run
   first-wins semantics). One-time, lossless except for duplicate rows' properties.
2. **Add the UNIQUE index** `uq_relationships_edge`. A UNIQUE *index* (not a table
   constraint) so the migration is portable to sqlite, which cannot
   `ALTER TABLE ADD CONSTRAINT`. `add_relationship` uses it as the
   `ON CONFLICT DO NOTHING` target (first-wins; ADR-022 Q1).
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0004_relationships_unique"
down_revision: str | None = "0003_audit_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EDGE_COLS = ("tenant_id", "src_entity_id", "dst_entity_id", "relationship_type")


def upgrade() -> None:
    # 1. Back-dedup: keep the lowest relationship_id per edge group. Portable SQL
    #    (works on Postgres + sqlite) — no correlated subquery, just NOT IN over a
    #    grouped MIN.
    op.execute(
        "DELETE FROM relationships WHERE relationship_id NOT IN ("
        "SELECT MIN(relationship_id) FROM relationships "
        "GROUP BY tenant_id, src_entity_id, dst_entity_id, relationship_type"
        ")"
    )
    # 2. The cross-run dedup backstop.
    op.create_index(
        "uq_relationships_edge",
        "relationships",
        list(_EDGE_COLS),
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_relationships_edge", table_name="relationships")
