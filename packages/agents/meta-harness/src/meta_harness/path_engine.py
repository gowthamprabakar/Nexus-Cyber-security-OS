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


# --- B3/B4: novelty filter + scoring → the candidate tier ----------------------------------------

#: (source_marker, sink_marker) pairs a NAMED archetype already reports. A generic path whose pair
#: is here is a duplicate of a named detector (which reports it better) → dropped. Everything else is
#: a NOVEL source→impact combination we have no named detector for — the candidate's reason to exist.
NAMED_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {
        ("public_resource", "sensitive_data"),  # public_secret / public_unencrypted / crown_jewel
        ("public_resource", "known_vulnerability"),  # internet_exposed_vulnerable
        ("privileged_workload", "known_vulnerability"),  # privileged_vulnerable
        ("external_identity", "sensitive_data"),  # external_trust
        ("exposed_ai_service", "sensitive_data"),  # exposed_ai_sensitive_data
        ("resource_policy_grant", "sensitive_data"),  # resource_based_data
        ("identity_principal", "sensitive_data"),  # fine_grained_data
        ("runtime_detection", "known_vulnerability"),  # runtime_exploit_vulnerable
        ("runtime_detection_file", "known_vulnerability"),  # runtime_exploit (file events)
    }
)

#: Candidate scores are capped strictly below the lowest NAMED severity (iac_misconfig=58), so a
#: confirmed finding always outranks an unverified candidate. Heuristic, not curated.
CANDIDATE_SCORE_CAP = 50

_SOURCE_WEIGHT = {
    "public_resource": 1.0,
    "external_identity": 0.95,
    "runtime_detection": 0.95,
    "runtime_detection_file": 0.9,
    "exposed_ai_service": 0.85,
    "privileged_workload": 0.85,
    "resource_policy_grant": 0.75,
    "identity_principal": 0.6,
}
_SINK_WEIGHT = {"sensitive_data": 1.0, "known_vulnerability": 0.85}


@dataclass(frozen=True, slots=True)
class CandidatePath:
    """A NOVEL generic path (no named archetype covers it), with a heuristic candidate score.

    ``confidence`` is always ``"candidate"`` — unverified, heuristically scored, capped below every
    named archetype. The candidate tier is for review ("what should we name next?"), not the
    customer-facing confirmed list.
    """

    path: GenericPath
    score: int
    confidence: str = "candidate"

    @property
    def pair(self) -> tuple[str, str]:
        return (self.path.source_marker, self.path.sink_marker)


def is_novel(path: GenericPath) -> bool:
    """True when no named archetype covers this path's (source, sink) combination."""
    return (path.source_marker, path.sink_marker) not in NAMED_PAIRS


def score_path(path: GenericPath) -> int:
    """A heuristic candidate score: source x sink severity, decayed by path length, capped."""
    source = _SOURCE_WEIGHT.get(path.source_marker, 0.6)
    sink = _SINK_WEIGHT.get(path.sink_marker, 0.8)
    decay = 1.0 / (1.0 + 0.25 * (len(path.hops) - 1))  # 1 hop = no decay; longer = more tenuous
    return max(1, round(CANDIDATE_SCORE_CAP * source * sink * decay))


async def find_candidate_paths(
    store: SemanticStore, tenant_id: str, *, max_depth: int = DEFAULT_MAX_DEPTH, limit: int = 20
) -> list[CandidatePath]:
    """Novel source→sink paths (no named archetype covers them), scored, worst-first, top ``limit``.

    Dedups to the shortest (most direct) path per (source, sink) node pair, so N routes between the
    same two nodes collapse to one candidate. The top-N cap bounds output; callers should surface
    the cap so a truncated list never reads as complete.
    """
    novel = [
        p for p in await find_generic_paths(store, tenant_id, max_depth=max_depth) if is_novel(p)
    ]
    shortest: dict[tuple[str, str], GenericPath] = {}
    for p in novel:
        key = (p.source_id, p.sink_id)
        if key not in shortest or len(p.hops) < len(shortest[key].hops):
            shortest[key] = p
    candidates = [CandidatePath(p, score_path(p)) for p in shortest.values()]
    candidates.sort(key=lambda c: (-c.score, len(c.path.hops), c.path.source_id))
    return candidates[:limit]


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


__all__ = [
    "CANDIDATE_SCORE_CAP",
    "DEFAULT_MAX_DEPTH",
    "NAMED_PAIRS",
    "CandidatePath",
    "GenericPath",
    "PathHop",
    "find_candidate_paths",
    "find_generic_paths",
    "is_novel",
    "score_path",
]
