"""`memory_neighbors_walk` — F.5 SemanticStore consumer for D.7 (Task 4).

Thin async wrapper around `charter.memory.SemanticStore.neighbors`.
The investigation pipeline calls this when an audit trail names an
entity (host, principal, finding) and D.7 needs the entity's neighbors
to scope the investigation: "what else is connected to this compromised
host within 3 hops?"

Per ADR-005 the wrapper is `async` so it fans out alongside the audit
trail query (Task 3) and the sibling-findings reader (Task 5) under
`asyncio.TaskGroup`.

D.7 enforces no additional depth cap beyond F.5's `MAX_TRAVERSAL_DEPTH = 3`.
The store raises `ValueError` on out-of-range depth; the tool
propagates rather than wrapping — D.7 doesn't pretend to know better
than F.5 about safe traversal bounds.
"""

from __future__ import annotations

from charter.memory import EntityRow, SemanticStore


async def memory_neighbors_walk(
    *,
    semantic_store: SemanticStore,
    tenant_id: str,
    entity_id: str,
    depth: int,
    edge_types: tuple[str, ...] | None = None,
) -> tuple[EntityRow, ...]:
    """Return entities reachable from `entity_id` within `depth` hops.

    Tenant-scoped via the underlying store's application-level filter
    + Postgres RLS (when running on Postgres). On aiosqlite, the
    application filter alone provides isolation during unit tests.

    `depth` must be in `[1, MAX_TRAVERSAL_DEPTH]`; out-of-range raises
    `ValueError` from the store.

    Returns events excluding the seed entity itself, ordered by the
    BFS discovery the store performs. Unknown seed → empty tuple.
    """
    rows = await semantic_store.neighbors(
        tenant_id=tenant_id,
        entity_id=entity_id,
        depth=depth,
        edge_types=edge_types,
    )
    return tuple(rows)


__all__ = ["memory_neighbors_walk"]
