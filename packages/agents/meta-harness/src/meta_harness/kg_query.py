"""Fleet-graph read queries — A.4 Meta-Harness `kg_query` (Stage 3 PR2).

Read-only correlation surface over the Postgres `SemanticStore`: turns the fleet inventory graph
(typed nodes + edges written by every agent `kg_writer`, ADR-018/019) into two 3-hop answers:

- **blast radius** — what is reachable *downstream* of a node (outgoing BFS). Built directly on
  `SemanticStore.neighbors` (which returns reachable entities).
- **attack path** — the actual edge chain(s) *from* one node *to* another. `neighbors` discards the
  edges that connect nodes, so this reconstructs paths in-consumer via the ADR-022 edge accessor
  `SemanticStore.get_relationships_from` (single-hop) + a depth-bounded BFS **here** (the traversal
  logic stays in the consumer, not in charter).

Depth is capped at `MAX_TRAVERSAL_DEPTH` (3, P-6) — the same cap the substrate enforces.
Tenant-scoped: every read pins `customer_id` (ADR-007). **Read-only** — this writes nothing; the
findings-as-decorations migration (`ATTACK_PATH` / `BLAST_RADIUS_RECORD` graph nodes) stays
deferred. A.4-only consumer this cycle (#718-D4).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.semantic import (
    MAX_TRAVERSAL_DEPTH,
    EntityRow,
    RelationshipRow,
    SemanticStore,
)


@dataclass(frozen=True, slots=True)
class BlastRadiusResult:
    """What is reachable downstream of `seed_entity_id` within `depth` hops (read-only)."""

    seed_entity_id: str
    depth: int
    edge_types: tuple[str, ...] | None
    reachable: tuple[EntityRow, ...]

    @property
    def count(self) -> int:
        return len(self.reachable)


@dataclass(frozen=True, slots=True)
class PathEdge:
    """One directed hop in a reconstructed attack path."""

    src_entity_id: str
    dst_entity_id: str
    relationship_type: str


@dataclass(frozen=True, slots=True)
class AttackPathResult:
    """All simple edge chains from `src_entity_id` to `dst_entity_id` within `max_depth` (read-only)."""

    src_entity_id: str
    dst_entity_id: str
    max_depth: int
    paths: tuple[tuple[PathEdge, ...], ...]

    @property
    def found(self) -> bool:
        return bool(self.paths)

    @property
    def shortest(self) -> tuple[PathEdge, ...] | None:
        """The fewest-hops path, or ``None`` when no path exists."""
        return min(self.paths, key=len) if self.paths else None


@dataclass(frozen=True, slots=True)
class ToxicCombination:
    """A public-data-exposure attack path: over-permissioned principal → public
    bucket → sensitive data. The `path` is the evidence chain (2 edges)."""

    principal_id: str
    resource_id: str
    data_classification_id: str
    path: tuple[PathEdge, PathEdge]


# Secret-type data classifications (data-security ClassifierLabel secret labels). A public
# resource exposing one of these is a publicly-readable credential — path 3 (ADR-023).
_SECRET_DATA_TYPES = frozenset({"aws_access_key", "jwt", "generic_api_token"})


@dataclass(frozen=True, slots=True)
class PublicSecretExposure:
    """A public resource that EXPOSES_DATA a secret-type classification (a publicly-
    readable credential). `data_type` is the secret kind (e.g. ``aws_access_key``)."""

    resource_id: str
    data_classification_id: str
    data_type: str


def _validate_depth(depth: int) -> int:
    if depth < 1 or depth > MAX_TRAVERSAL_DEPTH:
        raise ValueError(f"depth must be in [1, {MAX_TRAVERSAL_DEPTH}], got {depth}")
    return depth


class KgQuery:
    """Tenant-scoped read-only correlation queries over the fleet graph.

    Mirrors the agent `kg_writer` shape: constructed with `(SemanticStore, customer_id)`; every
    read pins the tenant. No writes.
    """

    def __init__(self, semantic_store: SemanticStore, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id

    async def blast_radius(
        self,
        *,
        entity_id: str,
        edge_types: tuple[str, ...] | None = None,
        depth: int = MAX_TRAVERSAL_DEPTH,
    ) -> BlastRadiusResult:
        """Entities reachable downstream of `entity_id` within `depth` outgoing hops.

        Pure consumer of `SemanticStore.neighbors` — no new charter dependency.
        """
        depth = _validate_depth(depth)
        reachable = await self._semantic_store.neighbors(
            tenant_id=self._customer_id,
            entity_id=entity_id,
            depth=depth,
            edge_types=edge_types,
        )
        return BlastRadiusResult(
            seed_entity_id=entity_id,
            depth=depth,
            edge_types=edge_types,
            reachable=tuple(reachable),
        )

    async def attack_path(
        self,
        *,
        src_entity_id: str,
        dst_entity_id: str,
        edge_types: tuple[str, ...] | None = None,
        max_depth: int = MAX_TRAVERSAL_DEPTH,
    ) -> AttackPathResult:
        """All simple edge chains from `src` to `dst` within `max_depth` hops.

        Depth-bounded BFS over the ADR-022 `get_relationships_from` edge accessor — the path
        reconstruction lives here (the consumer), not in charter. Cycles are excluded (a node
        never repeats within a single path). Returns an empty result when src == dst.
        """
        max_depth = _validate_depth(max_depth)
        if src_entity_id == dst_entity_id:
            return AttackPathResult(src_entity_id, dst_entity_id, max_depth, ())

        paths: list[tuple[PathEdge, ...]] = []
        # Seed: 1-edge paths out of src.
        frontier: list[tuple[PathEdge, ...]] = []
        for edge in await self._edges_from(src_entity_id, edge_types):
            step = PathEdge(edge.src_entity_id, edge.dst_entity_id, edge.relationship_type)
            if edge.dst_entity_id == dst_entity_id:
                paths.append((step,))
            else:
                frontier.append((step,))

        # Expand one hop at a time until the depth cap. `current_len` is the edge-count of the
        # paths currently in `frontier`.
        current_len = 1
        while frontier and current_len < max_depth:
            next_frontier: list[tuple[PathEdge, ...]] = []
            for path in frontier:
                tail = path[-1].dst_entity_id
                visited = {src_entity_id, *(e.dst_entity_id for e in path)}
                for edge in await self._edges_from(tail, edge_types):
                    if edge.dst_entity_id in visited:
                        continue  # no cycles within a single path
                    step = PathEdge(edge.src_entity_id, edge.dst_entity_id, edge.relationship_type)
                    extended = (*path, step)
                    if edge.dst_entity_id == dst_entity_id:
                        paths.append(extended)
                    else:
                        next_frontier.append(extended)
            frontier = next_frontier
            current_len += 1

        return AttackPathResult(src_entity_id, dst_entity_id, max_depth, tuple(paths))

    async def find_public_data_exposure(
        self, *, over_permissioned_principal_ids: Sequence[str]
    ) -> list[ToxicCombination]:
        """Find principal --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data paths.

        EXPOSES_DATA is only written for public buckets, so its presence proves both
        the public and sensitive-data legs. Read-only; seeded by the caller with the
        over-permissioned principals (from identity's OVERPRIVILEGE findings).
        """
        hits: list[ToxicCombination] = []
        for principal_id in over_permissioned_principal_ids:
            for access in await self._edges_from(principal_id, (EdgeType.HAS_ACCESS_TO.value,)):
                bucket_id = access.dst_entity_id
                for expose in await self._edges_from(bucket_id, (EdgeType.EXPOSES_DATA.value,)):
                    hits.append(
                        ToxicCombination(
                            principal_id=principal_id,
                            resource_id=bucket_id,
                            data_classification_id=expose.dst_entity_id,
                            path=(
                                PathEdge(principal_id, bucket_id, access.relationship_type),
                                PathEdge(bucket_id, expose.dst_entity_id, expose.relationship_type),
                            ),
                        )
                    )
        return hits

    async def find_public_secret_exposure(self) -> list[PublicSecretExposure]:
        """Find public resources that EXPOSES_DATA a secret-type classification.

        EXPOSES_DATA is written only for public buckets, so its presence proves the
        resource is public; we keep only edges to a SECRET data-type — a publicly-readable
        credential. Read-only; enumerates the tenant's CLOUD_RESOURCE nodes (no seed)."""
        hits: list[PublicSecretExposure] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for resource in resources:
            for expose in await self._edges_from(
                resource.entity_id, (EdgeType.EXPOSES_DATA.value,)
            ):
                dc = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                )
                if dc is None:
                    continue
                data_type = str(dc.properties.get("data_type", ""))
                if data_type in _SECRET_DATA_TYPES:
                    hits.append(
                        PublicSecretExposure(
                            resource_id=resource.entity_id,
                            data_classification_id=dc.entity_id,
                            data_type=data_type,
                        )
                    )
        return hits

    async def _edges_from(
        self, entity_id: str, edge_types: tuple[str, ...] | None
    ) -> list[RelationshipRow]:
        return await self._semantic_store.get_relationships_from(
            tenant_id=self._customer_id,
            src_entity_id=entity_id,
            edge_types=edge_types,
        )


__all__ = [
    "AttackPathResult",
    "BlastRadiusResult",
    "KgQuery",
    "PathEdge",
    "PublicSecretExposure",
    "ToxicCombination",
]
