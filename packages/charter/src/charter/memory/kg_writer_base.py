"""Shared knowledge-graph writer base (ADR-019).

The thin, reusable base for every agent's ``kg_writer`` — extracted from the
copy-pattern that the v0.2/v0.3 agents (cloud-posture, compliance, threat-intel,
synthesis, curiosity, meta-harness) each re-implemented. v0.4 Stage 1/2 add ~6 more
writers (D.3-runtime, D.4-data, D.6-k8s, D.4-network, D.2-identity, D.14-appsec);
12 writers justify a single base (ADR-019; operator decision #718-D1).

Responsibilities of the base (so each agent stops re-implementing them):

- **Tenant scoping** — every write is pinned to the writer's ``customer_id``; the
  base never accepts a per-call tenant, so cross-tenant writes are impossible by
  construction (ADR-007).
- **Typed vocabulary** — nodes/edges are typed by the ADR-018 catalogue
  (:class:`NodeCategory` / :class:`EdgeType`), not free strings.
- **Within-run edge dedup** — ``SemanticStore.add_relationship`` is INSERT-only, so
  repeated ``(src, dst, edge)`` triples within a run would duplicate. The base keeps a
  per-instance ``set`` and skips repeats. (Cross-run dedup — a DB ``UNIQUE`` constraint
  — is a separate Stage 3 PR, #718-D3; out of scope here.)
- **Opt-in / no-op** — when no ``SemanticStore`` is injected the writer is inert
  (single-tenant opt-in default, Path-B operating rule); methods short-circuit.

Agents subclass this and add their domain methods (e.g. ``upsert_repository`` +
``BUILT_FROM`` edges), calling :meth:`upsert_node` / :meth:`add_edge`. This module
changes no ``SemanticStore`` behaviour (it composes the existing API).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from charter.memory.graph_types import EdgeType, NodeCategory

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore


class KnowledgeGraphWriterBase:
    """Tenant-scoped, typed, dedup-aware base for agent knowledge-graph writers."""

    def __init__(self, semantic_store: SemanticStore | None, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id
        # within-run edge dedup: {(src_id, dst_id, edge_value)}
        self._seen_edges: set[tuple[str, str, str]] = set()

    @property
    def enabled(self) -> bool:
        """True when a store is injected (writes are live); False = inert no-op."""
        return self._semantic_store is not None

    async def upsert_node(
        self,
        category: NodeCategory,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str | None:
        """Idempotent node upsert, tenant-scoped + typed by the catalogue.

        Returns the entity_id (for edge wiring), or ``None`` when inert (no store).
        Identity collapses to ``(customer_id, category, external_id)`` — the
        SemanticStore's composite key.
        """
        if self._semantic_store is None:
            return None
        return await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type=category.value,
            external_id=external_id,
            properties=dict(properties or {}),
        )

    async def add_edge(
        self,
        src_entity_id: str,
        dst_entity_id: str,
        edge: EdgeType,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Write a typed directed edge, with within-run dedup.

        Skips when inert, when either endpoint id is ``None`` (an upstream
        inert/failed upsert), or when this ``(src, dst, edge)`` triple was already
        written by this instance.
        """
        if self._semantic_store is None:
            return
        if not src_entity_id or not dst_entity_id:
            return
        key = (src_entity_id, dst_entity_id, edge.value)
        if key in self._seen_edges:
            return
        await self._semantic_store.add_relationship(
            tenant_id=self._customer_id,
            src_entity_id=src_entity_id,
            dst_entity_id=dst_entity_id,
            relationship_type=edge.value,
            properties=dict(properties or {}),
        )
        self._seen_edges.add(key)


__all__ = ["KnowledgeGraphWriterBase"]
