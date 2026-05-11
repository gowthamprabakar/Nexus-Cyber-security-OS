"""Production SQLAlchemy 2.0 models for the Nexus memory engines (F.5).

Four tables back the three memory engines:

- **`episodes`** (episodic memory) — every agent run event that warrants
  long-term storage. Carries an optional pgvector embedding so the
  episodic store can do approximate-nearest-neighbour similarity search
  across past events. BRIN-friendly time ordering for the common
  "what happened today" query.

- **`playbooks`** (procedural memory) — versioned NLAH text + action
  policies, keyed by a hierarchical `path` (e.g.
  `remediation.s3.public_bucket`). Only one row per `(tenant_id, path)`
  is `active=True` at a time; older versions are kept for audit history.

- **`entities`** + **`relationships`** (semantic memory) — entity-
  relationship knowledge graph. Nodes are typed (`host`, `principal`,
  `finding`, etc.) with a `(tenant_id, entity_type, external_id)`
  natural key for upsert idempotency. Edges have `src` / `dst` /
  `relationship` triples with a JSONB `properties` payload. Recursive
  CTEs over `relationships` give us cheap graph traversal up to ~3 hops
  on per-tenant data.

**Production-grade discipline (F.5 Task 1).** This module ships real
models a customer's `Base.metadata.create_all` can materialize against
aiosqlite, Postgres, or any SQLAlchemy 2.0 dialect. The Postgres-only
column types (JSONB native, pgvector VECTOR, LTREE) appear in the
alembic migration (Task 2) but are written as dialect-portable
fall-backs here (JSON, JSON-as-vector, String) so unit tests run
against aiosqlite while production runs against Postgres. The
SQLAlchemy `with_variant` mechanism keeps both paths honest.

**Per-tenant isolation.** Every table carries `tenant_id` (ULID, 26
chars) as a leading column. Row-Level Security policies (Task 7) bind
queries to the active tenant via `current_setting('app.tenant_id')`;
`MemoryService.session(tenant_id=...)` (Task 9) sets the variable.
Application-side `WHERE tenant_id = ?` is the secondary defence.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON, TypeDecorator

# Embedding vector dimensionality. Matches OpenAI's text-embedding-3-small and
# the FakeEmbeddingProvider (F.5 Task 4). Production deployments can override
# via a dedicated migration if they swap providers; v0.1 is fixed.
EMBEDDING_DIM = 1536


class _PortableVector(TypeDecorator[list[float]]):
    """Dialect-portable VECTOR(N) — Postgres-native pgvector, JSON fallback elsewhere.

    Unit tests run against aiosqlite where `pgvector` does not exist. The
    JSON fallback stores the same float list and is good enough for
    schema-shape tests; ANN queries (Task 3's `EpisodicStore.search_similar`)
    are gated behind the live-Postgres integration test (Task 10).
    """

    impl = JSON
    cache_ok = True

    def __init__(self, dim: int = EMBEDDING_DIM) -> None:
        super().__init__()
        self.dim = dim

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            # Lazy import — pgvector ships its SQLAlchemy plugin but isn't
            # available when running against sqlite/aiosqlite.
            from pgvector.sqlalchemy import Vector

            return dialect.type_descriptor(Vector(self.dim))
        return dialect.type_descriptor(JSON())


class _PortableLtree(TypeDecorator[str]):
    """Dialect-portable LTREE — Postgres-native LTREE, String fallback elsewhere.

    Hierarchical paths look like `remediation.s3.public_bucket`. The
    String fallback supports equality + prefix lookups but not the
    Postgres `<@` / `@>` operators; subtree queries (Task 5) gate the
    LTREE-specific operators behind a dialect check.
    """

    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(postgresql.LTREE())  # type: ignore[attr-defined]
        return dialect.type_descriptor(String(512))


class _PortableJSONB(TypeDecorator[dict[str, Any]]):
    """Dialect-portable JSONB — Postgres-native JSONB, JSON fallback elsewhere.

    Postgres callers get GIN-indexable JSONB; aiosqlite tests get the
    standard JSON type. The semantic difference (sort key normalization,
    binary storage) doesn't matter for unit tests.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(postgresql.JSONB())
        return dialect.type_descriptor(JSON())


class Base(DeclarativeBase):
    """Declarative base for all charter-memory tables.

    Lives in `charter.memory.models` (Apache 2.0). Per-agent tables that
    layer on top of these can declare their own `Base` and migrate
    independently — they share the Postgres instance but not the
    declarative metadata.
    """


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EpisodeModel(Base):
    """One agent-run event in episodic memory.

    Inserted by `EpisodicStore.append_event` (Task 3). Indexed for the
    three common read patterns:

    - "fetch every event for this correlation_id" → ix_episodes_correlation
    - "fetch this tenant's recent events" → ix_episodes_tenant_emitted (DESC)
    - "find events similar to this embedding" → ix_episodes_embedding_ivf
      (Postgres only; created by the alembic migration in Task 2)
    """

    __tablename__ = "episodes"

    episode_id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer(), "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    tenant_id: Mapped[str] = mapped_column(String(26), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(32), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(_PortableJSONB(), nullable=False)
    embedding: Mapped[list[float] | None] = mapped_column(_PortableVector(), nullable=True)
    emitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        Index("ix_episodes_tenant_emitted", "tenant_id", "emitted_at"),
        Index("ix_episodes_correlation", "correlation_id"),
    )


class PlaybookModel(Base):
    """One versioned playbook in procedural memory.

    `(tenant_id, path, version)` is the natural key. Exactly one row per
    `(tenant_id, path)` has `active=True` at any time; older versions
    are retained for compliance / rollback. `ProceduralStore.publish_version`
    (Task 5) bumps `version` atomically and flips the prior active row
    to `False`.
    """

    __tablename__ = "playbooks"

    playbook_id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer(), "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    tenant_id: Mapped[str] = mapped_column(String(26), nullable=False)
    path: Mapped[str] = mapped_column(_PortableLtree(), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    body: Mapped[dict[str, Any]] = mapped_column(_PortableJSONB(), nullable=False)
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "path", "version", name="uq_playbooks_tenant_path_version"),
        Index("ix_playbooks_tenant_path", "tenant_id", "path"),
    )


class EntityModel(Base):
    """A node in the semantic-memory knowledge graph.

    `(tenant_id, entity_type, external_id)` is the natural upsert key.
    `entity_id` (ULID) is the synthetic key referenced by relationships.
    `properties` is a JSONB blob carrying type-specific attributes
    (e.g. for a `host` entity: hostname, image, namespace).
    """

    __tablename__ = "entities"

    entity_id: Mapped[str] = mapped_column(String(26), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(26), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(
        _PortableJSONB(), nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    outgoing: Mapped[list[RelationshipModel]] = relationship(
        back_populates="src_entity",
        foreign_keys="RelationshipModel.src_entity_id",
        cascade="all, delete-orphan",
    )
    incoming: Mapped[list[RelationshipModel]] = relationship(
        back_populates="dst_entity",
        foreign_keys="RelationshipModel.dst_entity_id",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "entity_type", "external_id", name="uq_entities_tenant_type_external"
        ),
        Index("ix_entities_tenant_type", "tenant_id", "entity_type"),
    )


class RelationshipModel(Base):
    """A directed edge in the semantic-memory knowledge graph.

    `src → relationship → dst`. Both endpoints are foreign keys to
    `entities.entity_id` with ON DELETE CASCADE so a deleted entity
    cleanly drops its edges. `properties` carries edge-type-specific
    attributes (e.g. for `RUNS_ON`: timestamp, container_id).
    """

    __tablename__ = "relationships"

    relationship_id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer(), "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    tenant_id: Mapped[str] = mapped_column(String(26), nullable=False)
    src_entity_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("entities.entity_id", ondelete="CASCADE"),
        nullable=False,
    )
    dst_entity_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("entities.entity_id", ondelete="CASCADE"),
        nullable=False,
    )
    # `relationship_type` rather than `relationship` to avoid colliding
    # with `sqlalchemy.orm.relationship()` in this class body.
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(
        _PortableJSONB(), nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    src_entity: Mapped[EntityModel] = relationship(
        back_populates="outgoing",
        foreign_keys=[src_entity_id],
    )
    dst_entity: Mapped[EntityModel] = relationship(
        back_populates="incoming",
        foreign_keys=[dst_entity_id],
    )

    __table_args__ = (
        Index("ix_relationships_src_type", "src_entity_id", "relationship_type"),
        Index("ix_relationships_dst_type", "dst_entity_id", "relationship_type"),
        Index("ix_relationships_tenant", "tenant_id"),
    )


# Re-exports kept here so `charter.memory.__init__` only re-exports
# symbols this module actually defines.
__all__ = [
    "EMBEDDING_DIM",
    "Base",
    "EntityModel",
    "EpisodeModel",
    "PlaybookModel",
    "RelationshipModel",
]
