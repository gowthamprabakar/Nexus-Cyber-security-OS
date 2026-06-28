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
    """One traversed edge: its type, the node it arrives at, and that node's human label (BP3)."""

    edge_type: str
    dst_entity_id: str
    dst_label: str = ""  # the dst node's external_id (ARN/URI/name) — for explainable render


@dataclass(frozen=True, slots=True)
class GenericPath:
    """One discovered source→sink path (the raw walker output, before scoring/novelty)."""

    source_id: str
    source_marker: str
    sink_id: str
    sink_marker: str
    hops: tuple[PathHop, ...]
    source_label: str = ""  # the source node's external_id — for explainable render (BP3)
    # The sink's risk signal, captured at the walk (BP2 scoring): a CVE's severity label + KEV
    # flag (exploitability), or a data classification's type (sensitivity). Empty when absent.
    sink_severity: str = ""
    sink_kev: bool = False
    sink_data_type: str = ""

    @property
    def edge_signature(self) -> tuple[str, ...]:
        """The ordered edge types — the shape used to match against named archetypes (B4)."""
        return tuple(h.edge_type for h in self.hops)

    @property
    def node_ids(self) -> tuple[str, ...]:
        """Every node on the path, source-first."""
        return (self.source_id, *(h.dst_entity_id for h in self.hops))

    @property
    def node_labels(self) -> tuple[str, ...]:
        """Every node's human label (external_id), source-first — falls back to entity_id (BP3)."""
        return (
            self.source_label or self.source_id,
            *(h.dst_label or h.dst_entity_id for h in self.hops),
        )


async def find_generic_paths(
    store: SemanticStore, tenant_id: str, *, max_depth: int = DEFAULT_MAX_DEPTH
) -> list[GenericPath]:
    """All source→sink paths within ``max_depth`` hops over attack-progressing edges."""
    paths: list[GenericPath] = []
    for source, marker in await _source_nodes(store, tenant_id):
        paths.extend(
            await _walk(store, tenant_id, source.entity_id, marker, max_depth, source.external_id)
        )
    return paths


# --- B3/B4 + BP1: novelty filter + scoring → the candidate tier ----------------------------------

#: (source_marker, sink_marker, edge_signature) SHAPES a NAMED archetype already reports — the
#: BP1 keystone. Novelty is keyed on the full shape, not just the (source, sink) PAIR: a NEW ROUTE
#: between an already-named pair (a different edge signature) is novel and surfaces, where the old
#: pair-based filter dropped it. This is what makes transitive / multi-domain chains discoverable.
#:
#: A generic path whose exact shape is here is a duplicate of a named detector (which reports it
#: better) → dropped. Every other source→sink shape is a combination no named detector covers.
#: MUST list every named shape the walker can actually generate (terminating at the first sink),
#: including ``internet_exposed_host_vulnerable`` — else it would surface as a false candidate.
#: The taxonomy test pins this against the named-archetype model so the two can't drift.
NAMED_SHAPES: frozenset[tuple[str, str, tuple[str, ...]]] = frozenset(
    {
        (
            "public_resource",
            "sensitive_data",
            ("EXPOSES_DATA",),
        ),  # public_secret / public_unencrypted
        (
            "public_resource",
            "known_vulnerability",
            ("RUNS_IMAGE", "VULNERABLE_TO"),
        ),  # internet_exposed_vulnerable
        (
            "public_resource",
            "known_vulnerability",
            ("VULNERABLE_TO",),
        ),  # internet_exposed_host_vulnerable (#15)
        (
            "privileged_workload",
            "known_vulnerability",
            ("RUNS_IMAGE", "VULNERABLE_TO"),
        ),  # privileged_vulnerable
        (
            "external_identity",
            "sensitive_data",
            ("HAS_ACCESS_TO", "EXPOSES_DATA"),
        ),  # external_trust
        (
            "exposed_ai_service",
            "sensitive_data",
            ("HAS_ACCESS_TO", "EXPOSES_DATA"),
        ),  # exposed_ai_sensitive_data
        ("resource_policy_grant", "sensitive_data", ("CONTAINS",)),  # resource_based_data
        (
            "identity_principal",
            "sensitive_data",
            ("HAS_ACCESS_TO", "EXPOSES_DATA"),
        ),  # fine_grained_data
        (
            "identity_principal",
            "sensitive_data",
            ("ASSUMES", "HAS_ACCESS_TO", "EXPOSES_DATA"),
        ),  # privilege_escalation
        (
            "runtime_detection",
            "known_vulnerability",
            ("EXECUTED_ON", "RUNS_IMAGE", "VULNERABLE_TO"),
        ),  # runtime_exploit
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

#: BP2 exploitability: a CVE sink's severity label → weight; KEV (known-exploited) bumps it up.
_CVE_SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.4}
_KEV_BOOST = 1.2

#: BP2 sensitivity: a data sink's classification → weight (regulated/credential data scores higher).
_HIGH_SENSITIVITY = frozenset(
    {"ssn", "pci", "phi", "credentials", "aws_access_key", "mrn", "cvv", "npi"}
)

#: BP2 per-edge progression risk — how certain/severe traversing this edge is. A path is gated by
#: its WEAKEST hop (a chain is only as strong as its least-certain progression), so the path's edge
#: factor is the min over its hops. Observed network hops (COMMUNICATES_WITH) carry more uncertainty
#: than a direct data-exposure edge; provenance edges (DEPLOYED_VIA / DEFINED_IN) weaker still.
_EDGE_RISK = {
    "EXPOSES_DATA": 1.0,
    "VULNERABLE_TO": 1.0,
    "MATCHES_INDICATOR": 1.0,
    "EXECUTED_ON": 0.95,
    "RUNS_IMAGE": 0.95,
    "HAS_ACCESS_TO": 0.9,
    "ASSUMES": 0.9,
    "EXPOSES_MODEL": 0.9,
    "OWNED_BY": 0.85,
    "CONTAINS": 0.8,
    "COMMUNICATES_WITH": 0.8,
    "DEPLOYED_VIA": 0.7,
    "DEFINED_IN": 0.7,
}


def _sink_factor(path: GenericPath) -> float:
    """The impact weight of the path's sink: exploitability (CVE) or sensitivity (data)."""
    if path.sink_marker == "known_vulnerability":
        base = _CVE_SEVERITY_WEIGHT.get(path.sink_severity.upper(), 0.7)
        return min(1.0, base * _KEV_BOOST) if path.sink_kev else base
    if path.sink_marker == "sensitive_data":
        return 1.0 if path.sink_data_type.lower() in _HIGH_SENSITIVITY else 0.75
    return 0.8


def _edge_factor(path: GenericPath) -> float:
    """The weakest-link progression risk over the path's hops (1.0 for a direct/0-hop sink)."""
    return min((_EDGE_RISK.get(e, 0.8) for e in path.edge_signature), default=1.0)


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
    """True when no named archetype covers this path's full SHAPE (source, sink, edge signature).

    BP1: route-aware. A path between an already-named (source, sink) pair is still novel if its
    edge signature differs from the named shape — a new route to a known impact is a new finding."""
    return (path.source_marker, path.sink_marker, path.edge_signature) not in NAMED_SHAPES


def score_path(path: GenericPath) -> int:
    """A heuristic candidate score (BP2), capped below every confirmed severity.

    Four signals, each in [0, 1], multiplied then scaled by the cap:
    - source exposure weight (a public resource outweighs a buried principal),
    - sink impact: CVE exploitability (severity x KEV) or data sensitivity,
    - weakest-edge progression risk (a chain is as strong as its least-certain hop),
    - length decay (a longer transitive chain is more tenuous).
    Calibration against a labeled scene set is BP8; this is the credible-ordering heuristic."""
    source = _SOURCE_WEIGHT.get(path.source_marker, 0.6)
    decay = 1.0 / (1.0 + 0.25 * (len(path.hops) - 1))  # 1 hop = no decay; longer = more tenuous
    score = CANDIDATE_SCORE_CAP * source * _sink_factor(path) * _edge_factor(path) * decay
    return max(1, round(score))


async def find_candidate_paths(
    store: SemanticStore, tenant_id: str, *, max_depth: int = DEFAULT_MAX_DEPTH, limit: int = 20
) -> list[CandidatePath]:
    """Novel source→sink paths (no named archetype covers them), scored, worst-first, top ``limit``.

    BP1 novelty is route-aware (shape, not just pair), but a novel-shaped route between two nodes a
    NAMED shape ALREADY connects is a redundant parallel edge (e.g. a public bucket carries both
    EXPOSES_DATA — the named public_secret — and a CONTAINS edge to the same data), not a new attack
    path. So a route is a candidate only when its shape is unnamed AND its exact (source, sink) node
    pair is not already named-covered in this graph: new routes to NEW impacts surface; duplicates of
    a named endpoint pair are dropped.

    Dedups to the shortest (most direct) path per (source, sink) node pair. The top-N cap bounds
    output; callers should surface the cap so a truncated list never reads as complete.
    """
    all_paths = await find_generic_paths(store, tenant_id, max_depth=max_depth)
    named_node_pairs = {(p.source_id, p.sink_id) for p in all_paths if not is_novel(p)}
    shortest: dict[tuple[str, str], GenericPath] = {}
    for p in all_paths:
        key = (p.source_id, p.sink_id)
        if not is_novel(p) or key in named_node_pairs:
            continue  # named shape, or the same endpoints a named shape already reports
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
    store: SemanticStore,
    tenant_id: str,
    source_id: str,
    source_marker: str,
    max_depth: int,
    source_label: str,
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
                new_hops = (
                    *hops,
                    PathHop(rel.relationship_type, rel.dst_entity_id, dst.external_id),
                )
                sink_marker = match_sink(dst.entity_type, dst.properties)
                if sink_marker:
                    # A sink is terminal impact — record the path; do not expand past it.
                    results.append(
                        GenericPath(
                            source_id,
                            source_marker,
                            dst.entity_id,
                            sink_marker,
                            new_hops,
                            source_label=source_label,
                            sink_severity=str(dst.properties.get("severity", "")),
                            sink_kev=dst.properties.get("kev") is True,
                            sink_data_type=str(dst.properties.get("data_type", "")),
                        )
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
    "NAMED_SHAPES",
    "CandidatePath",
    "GenericPath",
    "PathHop",
    "find_candidate_paths",
    "find_generic_paths",
    "is_novel",
    "score_path",
]
