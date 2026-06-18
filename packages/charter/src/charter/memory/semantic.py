"""`SemanticStore` — entity-relationship CRUD with graph traversal.

The third memory engine. Knowledge graph backed by the `entities` and
`relationships` tables: typed nodes joined by directed, typed edges.

Surface:

- `upsert_entity` is idempotent on `(tenant_id, entity_type, external_id)`.
  Returns a stable ULID `entity_id`. Properties merge rather than
  replace, so two agents can each contribute attributes for the same
  underlying object.
- `add_relationship` writes a directed edge `src --type--> dst`.
- `neighbors(entity_id, depth)` does a breadth-first traversal out to
  `depth` hops, optionally filtered by `edge_types`. Depth is capped
  at 3 in v0.1 — that cap is enforced here, not at the DB layer, so
  the recursive-CTE cost stays predictable.

On Postgres the traversal is a single recursive CTE. On aiosqlite
(unit tests) the same depth-bounded BFS runs iteratively in Python
over the same `relationships` rows. Both implementations satisfy the
identical "every entity reachable in ≤ depth hops, excluding the
seed entity itself" contract.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from ulid import ULID

from charter.audit import AuditLog
from charter.memory.audit import ACTION_ENTITY_UPSERTED, ACTION_RELATIONSHIP_ADDED
from charter.memory.models import EntityModel, RelationshipModel

MAX_TRAVERSAL_DEPTH = 3


class EntityRow:
    """Read-only DTO for an entity node."""

    __slots__ = (
        "created_at",
        "entity_id",
        "entity_type",
        "external_id",
        "properties",
        "tenant_id",
    )

    def __init__(
        self,
        *,
        entity_id: str,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any],
        created_at: datetime,
    ) -> None:
        self.entity_id = entity_id
        self.tenant_id = tenant_id
        self.entity_type = entity_type
        self.external_id = external_id
        self.properties = properties
        self.created_at = created_at


class RelationshipRow:
    """Read-only DTO for a directed edge (`src --type--> dst`).

    Returned by `get_relationships_from` so path consumers (e.g. the meta-harness
    `kg_query` attack-path reconstruction) can walk edges — `neighbors` returns only
    reachable *entities* and discards the edges that connect them.
    """

    __slots__ = (
        "created_at",
        "dst_entity_id",
        "properties",
        "relationship_id",
        "relationship_type",
        "src_entity_id",
        "tenant_id",
    )

    def __init__(
        self,
        *,
        relationship_id: int,
        tenant_id: str,
        src_entity_id: str,
        dst_entity_id: str,
        relationship_type: str,
        properties: dict[str, Any],
        created_at: datetime,
    ) -> None:
        self.relationship_id = relationship_id
        self.tenant_id = tenant_id
        self.src_entity_id = src_entity_id
        self.dst_entity_id = dst_entity_id
        self.relationship_type = relationship_type
        self.properties = properties
        self.created_at = created_at


class SemanticStore:
    """Typed async accessor over `entities` + `relationships`."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        audit_log: AuditLog | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit_log = audit_log

    async def upsert_entity(
        self,
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Idempotent insert keyed by `(tenant_id, entity_type, external_id)`.

        On hit: merges `properties` into the stored row (later writes
        win on key collisions) and returns the existing `entity_id`.
        On miss: inserts a fresh row with a new ULID and returns it.
        """
        props = dict(properties or {})
        async with self._session_factory.begin() as session:
            stmt = select(EntityModel).where(
                EntityModel.tenant_id == tenant_id,
                EntityModel.entity_type == entity_type,
                EntityModel.external_id == external_id,
            )
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if existing is not None:
                if props:
                    merged = {**existing.properties, **props}
                    await session.execute(
                        update(EntityModel)
                        .where(EntityModel.entity_id == existing.entity_id)
                        .values(properties=merged)
                    )
                return existing.entity_id

            entity_id = str(ULID())
            session.add(
                EntityModel(
                    entity_id=entity_id,
                    tenant_id=tenant_id,
                    entity_type=entity_type,
                    external_id=external_id,
                    properties=props,
                )
            )

        if self._audit_log is not None:
            self._audit_log.append(
                action=ACTION_ENTITY_UPSERTED,
                payload={
                    "tenant_id": tenant_id,
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                    "external_id": external_id,
                },
            )
        return entity_id

    async def get_entity(
        self,
        *,
        tenant_id: str,
        entity_id: str,
    ) -> EntityRow | None:
        stmt = select(EntityModel).where(
            EntityModel.tenant_id == tenant_id,
            EntityModel.entity_id == entity_id,
        )
        async with self._session_factory() as session:
            model = (await session.execute(stmt)).scalar_one_or_none()
            return self._row(model) if model is not None else None

    async def add_relationship(
        self,
        *,
        tenant_id: str,
        src_entity_id: str,
        dst_entity_id: str,
        relationship_type: str,
        properties: dict[str, Any] | None = None,
    ) -> int:
        """Write a directed edge, idempotent on `(tenant, src, dst, type)`.

        Cross-run dedup (ADR-022): a repeated write of the same edge is a no-op at
        the DB layer (`ON CONFLICT DO NOTHING` against `uq_relationships_edge`,
        first-wins) and returns the existing `relationship_id`. Properties are not
        part of the key, so a re-write with different properties does not create a
        second edge (and does not overwrite the first — Q1 DO_NOTHING).
        """
        async with self._session_factory.begin() as session:
            ins = pg_insert if session.bind.dialect.name == "postgresql" else sqlite_insert
            result = await session.execute(
                ins(RelationshipModel)
                .values(
                    tenant_id=tenant_id,
                    src_entity_id=src_entity_id,
                    dst_entity_id=dst_entity_id,
                    relationship_type=relationship_type,
                    properties=dict(properties or {}),
                )
                .on_conflict_do_nothing(
                    index_elements=[
                        "tenant_id",
                        "src_entity_id",
                        "dst_entity_id",
                        "relationship_type",
                    ]
                )
                .returning(RelationshipModel.relationship_id)
            )
            inserted_id = result.scalar_one_or_none()
            if inserted_id is None:
                # Conflict (edge already exists) → fetch the first-written id; no insert,
                # no audit emission (a dedup hit is not a graph mutation).
                existing = await session.execute(
                    select(RelationshipModel.relationship_id).where(
                        RelationshipModel.tenant_id == tenant_id,
                        RelationshipModel.src_entity_id == src_entity_id,
                        RelationshipModel.dst_entity_id == dst_entity_id,
                        RelationshipModel.relationship_type == relationship_type,
                    )
                )
                return int(existing.scalar_one())
            relationship_id = int(inserted_id)

        if self._audit_log is not None:
            self._audit_log.append(
                action=ACTION_RELATIONSHIP_ADDED,
                payload={
                    "tenant_id": tenant_id,
                    "relationship_id": relationship_id,
                    "src_entity_id": src_entity_id,
                    "dst_entity_id": dst_entity_id,
                    "relationship_type": relationship_type,
                },
            )
        return relationship_id

    async def neighbors(
        self,
        *,
        tenant_id: str,
        entity_id: str,
        depth: int = 1,
        edge_types: tuple[str, ...] | None = None,
    ) -> list[EntityRow]:
        """Breadth-first traversal out to `depth` hops.

        Returns every entity reachable in ≤ `depth` outgoing edges,
        excluding the seed `entity_id` itself. `depth` is clamped to
        `[1, MAX_TRAVERSAL_DEPTH]`; values outside the range raise
        `ValueError`.

        v0.1 runs the same iterative BFS on every dialect. Phase 1b
        will swap in a single recursive CTE for Postgres once the
        graph grows past the in-process traversal break-even.
        """
        if depth < 1 or depth > MAX_TRAVERSAL_DEPTH:
            raise ValueError(f"depth must be in [1, {MAX_TRAVERSAL_DEPTH}], got {depth}")

        async with self._session_factory() as session:
            visited: set[str] = {entity_id}
            frontier: set[str] = {entity_id}
            collected: list[str] = []
            for _ in range(depth):
                if not frontier:
                    break
                stmt = select(RelationshipModel.dst_entity_id).where(
                    RelationshipModel.tenant_id == tenant_id,
                    RelationshipModel.src_entity_id.in_(frontier),
                )
                if edge_types is not None:
                    stmt = stmt.where(RelationshipModel.relationship_type.in_(edge_types))
                result = await session.execute(stmt)
                next_frontier: set[str] = set()
                for (dst_id,) in result.all():
                    if dst_id not in visited:
                        visited.add(dst_id)
                        next_frontier.add(dst_id)
                        collected.append(dst_id)
                frontier = next_frontier

            if not collected:
                return []
            entities_stmt = select(EntityModel).where(
                EntityModel.tenant_id == tenant_id,
                EntityModel.entity_id.in_(collected),
            )
            rows = (await session.execute(entities_stmt)).scalars().all()
            return [self._row(m) for m in rows]

    async def get_relationships_from(
        self,
        *,
        tenant_id: str,
        src_entity_id: str,
        edge_types: tuple[str, ...] | None = None,
    ) -> list[RelationshipRow]:
        """Return a node's **outgoing edges** (optionally filtered by type).

        The minimal edge accessor path consumers need: `neighbors` returns reachable
        entities but discards the connecting edges, so attack-path reconstruction
        (meta-harness `kg_query`, ADR-022) walks edges through this instead. Read-only;
        tenant-scoped per ADR-007 — never returns another tenant's edges. The traversal
        logic (BFS / depth cap) stays in the consumer; this is a single-hop accessor.
        """
        if not tenant_id:
            raise ValueError("tenant_id must be a non-empty string")
        if not src_entity_id:
            raise ValueError("src_entity_id must be a non-empty string")
        stmt = select(RelationshipModel).where(
            RelationshipModel.tenant_id == tenant_id,
            RelationshipModel.src_entity_id == src_entity_id,
        )
        if edge_types is not None:
            stmt = stmt.where(RelationshipModel.relationship_type.in_(edge_types))
        async with self._session_factory() as session:
            models = (await session.execute(stmt)).scalars().all()
            return [self._edge_row(m) for m in models]

    async def list_entities_by_type(
        self,
        *,
        tenant_id: str,
        entity_type: str,
    ) -> list[EntityRow]:
        """List all entities of a given type for a tenant.

        Used by query-side consumers (e.g. D.12 Curiosity's
        coverage-gap detector) that scan the KG for aggregate state.
        Returns rows in insertion order; callers that need ordering
        guarantees should sort by ``EntityRow.created_at`` or by a
        property field. Returns ``[]`` when no entities of that type
        exist for the tenant.

        Tenant-scoped per ADR-007 v1.1 — never returns rows from
        other tenants. Cross-tenant reads must go through an
        explicit control-plane path (out of scope here).
        """
        if not tenant_id:
            raise ValueError("tenant_id must be a non-empty string")
        if not entity_type:
            raise ValueError("entity_type must be a non-empty string")
        stmt = select(EntityModel).where(
            EntityModel.tenant_id == tenant_id,
            EntityModel.entity_type == entity_type,
        )
        async with self._session_factory() as session:
            models = (await session.execute(stmt)).scalars().all()
            return [self._row(m) for m in models]

    @staticmethod
    def _row(model: EntityModel) -> EntityRow:
        return EntityRow(
            entity_id=model.entity_id,
            tenant_id=model.tenant_id,
            entity_type=model.entity_type,
            external_id=model.external_id,
            properties=dict(model.properties),
            created_at=model.created_at,
        )

    @staticmethod
    def _edge_row(model: RelationshipModel) -> RelationshipRow:
        return RelationshipRow(
            relationship_id=model.relationship_id,
            tenant_id=model.tenant_id,
            src_entity_id=model.src_entity_id,
            dst_entity_id=model.dst_entity_id,
            relationship_type=model.relationship_type,
            properties=dict(model.properties),
            created_at=model.created_at,
        )


__all__ = ["MAX_TRAVERSAL_DEPTH", "EntityRow", "RelationshipRow", "SemanticStore"]
