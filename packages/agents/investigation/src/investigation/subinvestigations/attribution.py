"""asset_enum + attribution enhancements (investigation v0.2 Task 8).

Additive enrichment for two more sub-investigation types (v0.1 untouched, eval byte-identical):

- **asset_enum**: ``enumerate_assets`` collects distinct asset entities from a live F.5
  semantic-graph walk, **depth-capped at the H5 bound** (``clamp_walk_depth``, WI-I11 — nodes
  beyond depth 3 are dropped).
- **attribution**: ``score_attribution`` assigns a **confidence** to each MITRE technique from
  the count of supporting evidence hits (more evidence -> higher confidence).

Pure + deterministic.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from investigation.tools.substrate_query import clamp_walk_depth

#: Confidence saturates at this many supporting evidence hits.
_CONFIDENCE_SATURATION = 3


def enumerate_assets(
    walk_nodes: Sequence[Mapping[str, Any]], *, requested_depth: int
) -> tuple[str, ...]:
    """Collect distinct asset entity ids from an F.5 graph walk, depth-capped (H5). Each node is
    ``{"entity_id": str, "type": str, "depth": int}``; nodes beyond the cap are dropped."""
    cap = clamp_walk_depth(requested_depth)
    seen: list[str] = []
    for node in walk_nodes:
        depth = node.get("depth", 0)
        entity_id = node.get("entity_id")
        within = isinstance(depth, int) and depth <= cap
        if within and isinstance(entity_id, str) and entity_id and entity_id not in seen:
            seen.append(entity_id)
    return tuple(seen)


@dataclass(frozen=True, slots=True)
class AttributionScore:
    technique_id: str
    confidence: float


def score_attribution(technique_hits: Mapping[str, int]) -> tuple[AttributionScore, ...]:
    """Score each MITRE technique: confidence = min(1.0, hits / saturation), ranked desc."""
    scores = [
        AttributionScore(
            technique_id=tid,
            confidence=round(min(1.0, max(hits, 0) / _CONFIDENCE_SATURATION), 3),
        )
        for tid, hits in technique_hits.items()
    ]
    return tuple(sorted(scores, key=lambda s: (-s.confidence, s.technique_id)))
