"""memory engines baseline — episodes / playbooks / entities / relationships (F.5 Task 2)

Revision ID: 0001_memory_baseline
Revises:
Create Date: 2026-05-12

Materializes the four tables backing charter.memory's three engines
(episodic / procedural / semantic). The dialect-portable column types
in `charter.memory.models` carry the cross-dialect basics; this
migration adds the production-grade **Postgres-only** indexes that
SQLAlchemy can't declare portably:

- `ix_episodes_payload_gin` — GIN over `payload jsonb_path_ops` for
  predicate pushdown on JSONB fields ("find every event where
  `payload->>'severity' = 'critical'`").
- `ix_episodes_embedding_ivf` — `ivfflat (embedding vector_cosine_ops)`
  for pgvector approximate-nearest-neighbour search in `EpisodicStore.
  search_similar` (Task 3).
- `ix_playbooks_path_gist` — GiST over LTREE for the `<@` / `@>`
  subtree-containment operators used by `ProceduralStore`'s
  hierarchical lookups (Task 5).

All three Postgres-only indexes are gated by a dialect check so this
migration runs against aiosqlite during unit tests without raising.
The Postgres `pgvector` and `ltree` extensions are created unconditionally
on Postgres (idempotent via `IF NOT EXISTS`).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# The migration reuses the dialect-portable TypeDecorators already shipped
# (and unit-tested) in charter.memory.models — single source of truth for
# the JSONB / pgvector / LTREE fallbacks.
from charter.memory.models import _PortableJSONB, _PortableLtree, _PortableVector

revision: str = "0001_memory_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if _is_postgres():
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")
        op.execute("CREATE EXTENSION IF NOT EXISTS ltree")

    # ---------------------------------------------------------------------
    # episodes
    # ---------------------------------------------------------------------
    op.create_table(
        "episodes",
        sa.Column(
            "episode_id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("tenant_id", sa.String(length=26), nullable=False),
        sa.Column("correlation_id", sa.String(length=32), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("payload", _PortableJSONB(), nullable=False),
        sa.Column("embedding", _PortableVector(dim=1536), nullable=True),
        sa.Column(
            "emitted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_episodes_tenant_emitted", "episodes", ["tenant_id", "emitted_at"])
    op.create_index("ix_episodes_correlation", "episodes", ["correlation_id"])

    # ---------------------------------------------------------------------
    # playbooks
    # ---------------------------------------------------------------------
    op.create_table(
        "playbooks",
        sa.Column(
            "playbook_id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("tenant_id", sa.String(length=26), nullable=False),
        sa.Column("path", _PortableLtree(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("body", _PortableJSONB(), nullable=False),
        sa.Column(
            "published_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "tenant_id", "path", "version", name="uq_playbooks_tenant_path_version"
        ),
    )
    op.create_index("ix_playbooks_tenant_path", "playbooks", ["tenant_id", "path"])

    # ---------------------------------------------------------------------
    # entities
    # ---------------------------------------------------------------------
    op.create_table(
        "entities",
        sa.Column("entity_id", sa.String(length=26), primary_key=True),
        sa.Column("tenant_id", sa.String(length=26), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("properties", _PortableJSONB(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "entity_type",
            "external_id",
            name="uq_entities_tenant_type_external",
        ),
    )
    op.create_index("ix_entities_tenant_type", "entities", ["tenant_id", "entity_type"])

    # ---------------------------------------------------------------------
    # relationships
    # ---------------------------------------------------------------------
    op.create_table(
        "relationships",
        sa.Column(
            "relationship_id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("tenant_id", sa.String(length=26), nullable=False),
        sa.Column(
            "src_entity_id",
            sa.String(length=26),
            sa.ForeignKey("entities.entity_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "dst_entity_id",
            sa.String(length=26),
            sa.ForeignKey("entities.entity_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("properties", _PortableJSONB(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_relationships_src_type",
        "relationships",
        ["src_entity_id", "relationship_type"],
    )
    op.create_index(
        "ix_relationships_dst_type",
        "relationships",
        ["dst_entity_id", "relationship_type"],
    )
    op.create_index("ix_relationships_tenant", "relationships", ["tenant_id"])

    # ---------------------------------------------------------------------
    # Postgres-only indexes (gated by dialect)
    # ---------------------------------------------------------------------
    if _is_postgres():
        op.execute(
            "CREATE INDEX ix_episodes_payload_gin ON episodes USING GIN (payload jsonb_path_ops)"
        )
        # ivfflat needs a populated table for the LIST count to mean anything;
        # 100 is the documented starter value. Phase 1b will recreate this
        # with a tuned LIST count after real production volume lands.
        op.execute(
            "CREATE INDEX ix_episodes_embedding_ivf "
            "ON episodes USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
        )
        op.execute("CREATE INDEX ix_playbooks_path_gist ON playbooks USING GIST (path)")


def downgrade() -> None:
    if _is_postgres():
        op.execute("DROP INDEX IF EXISTS ix_playbooks_path_gist")
        op.execute("DROP INDEX IF EXISTS ix_episodes_embedding_ivf")
        op.execute("DROP INDEX IF EXISTS ix_episodes_payload_gin")

    op.drop_index("ix_relationships_tenant", table_name="relationships")
    op.drop_index("ix_relationships_dst_type", table_name="relationships")
    op.drop_index("ix_relationships_src_type", table_name="relationships")
    op.drop_table("relationships")

    op.drop_index("ix_entities_tenant_type", table_name="entities")
    op.drop_table("entities")

    op.drop_index("ix_playbooks_tenant_path", table_name="playbooks")
    op.drop_table("playbooks")

    op.drop_index("ix_episodes_correlation", table_name="episodes")
    op.drop_index("ix_episodes_tenant_emitted", table_name="episodes")
    op.drop_table("episodes")
