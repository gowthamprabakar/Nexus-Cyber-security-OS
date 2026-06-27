"""Generic attack-path walker — the Track B engine (B2).

A multi-source bounded BFS over the typed graph: start at every node matching a SOURCE marker
(exposure), follow only TRAVERSABLE (attack-progressing) edges, and record a path whenever it
reaches a node matching a SINK marker (sensitive data / vulnerability). Unlike the named detectors
(each a hardcoded source→sink shape), this discovers ANY source→sink path within the depth bound —
so it re-discovers the named shapes AND finds combinations no named detector covers.

Depth-bounded (default 3, the substrate's traversal cap; the discovery run raises this to 4 as a
measured step). Cycle-excluding (a node appears at most once per path). Read-only. Scoring + the
novelty filter (drop shapes a named archetype already reports) + the candidate tier are B3/B4/B5;
this is just the walker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from meta_harness.path_taxonomy import (
    SOURCE_MARKERS,
    is_traversable,
    match_sink,
    match_source,
)

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

#: The substrate's default traversal depth; the discovery run raises this (a measured step).
DEFAULT_MAX_DEPTH = 3


@dataclass(frozen=True, slots=True)
class PathHop:
    """One traversed edge: its type + the node it arrives at."""

    edge_type: str
    dst_entity_id: str


@dataclass(frozen=True, slots=True)
class GenericPath:
    """One discovered source→sink path (the raw walker output, before scoring/novelty)."""

    source_id: str
    source_marker: str
    sink_id: str
    sink_marker: str
    hops: tuple[PathHop, ...]

    @property
    def edge_signature(self) -> tuple[str, ...]:
        """The ordered edge types — the shape used to match against named archetypes (B4)."""
        return tuple(h.edge_type for h in self.hops)

    @property
    def node_ids(self) -> tuple[str, ...]:
        """Every node on the path, source-first."""
        return (self.source_id, *(h.dst_entity_id for h in self.hops))


async def find_generic_paths(
    store: SemanticStore, tenant_id: str, *, max_depth: int = DEFAULT_MAX_DEPTH
) -> list[GenericPath]:
    """All source→sink paths within ``max_depth`` hops over attack-progressing edges."""
    paths: list[GenericPath] = []
    for source, marker in await _source_nodes(store, tenant_id):
        paths.extend(await _walk(store, tenant_id, source.entity_id, marker, max_depth))
    return paths


async def _source_nodes(store: SemanticStore, tenant_id: str) -> list[tuple[object, str]]:
    """Every node matching a source marker, paired with the marker name."""
    out: list[tuple[object, str]] = []
    for category in {m.category for m in SOURCE_MARKERS}:
        for node in await store.list_entities_by_type(
            tenant_id=tenant_id, entity_type=category.value
        ):
            marker = match_source(node.entity_type, node.properties)
            if marker:
                out.append((node, marker))
    return out


async def _walk(
    store: SemanticStore, tenant_id: str, source_id: str, source_marker: str, max_depth: int
) -> list[GenericPath]:
    """Bounded, cycle-excluding BFS from one source; record a path at every sink reached."""
    results: list[GenericPath] = []
    # frontier entries: (current node id, hops so far, nodes visited on this path)
    frontier: list[tuple[str, tuple[PathHop, ...], frozenset[str]]] = [
        (source_id, (), frozenset({source_id}))
    ]
    for _ in range(max_depth):
        next_frontier: list[tuple[str, tuple[PathHop, ...], frozenset[str]]] = []
        for node_id, hops, visited in frontier:
            for rel in await store.get_relationships_from(
                tenant_id=tenant_id, src_entity_id=node_id
            ):
                if not is_traversable(rel.relationship_type) or rel.dst_entity_id in visited:
                    continue
                dst = await store.get_entity(tenant_id=tenant_id, entity_id=rel.dst_entity_id)
                if dst is None:
                    continue
                new_hops = (*hops, PathHop(rel.relationship_type, rel.dst_entity_id))
                sink_marker = match_sink(dst.entity_type, dst.properties)
                if sink_marker:
                    # A sink is terminal impact — record the path; do not expand past it.
                    results.append(
                        GenericPath(source_id, source_marker, dst.entity_id, sink_marker, new_hops)
                    )
                else:
                    next_frontier.append(
                        (rel.dst_entity_id, new_hops, visited | {rel.dst_entity_id})
                    )
        frontier = next_frontier
    return results


__all__ = ["DEFAULT_MAX_DEPTH", "GenericPath", "PathHop", "find_generic_paths"]
