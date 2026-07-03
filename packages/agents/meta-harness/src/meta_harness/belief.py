"""v0.5 — noisy-OR belief propagation over extracted attack paths (the belief-network piece).

A sink reachable by multiple independent routes is more likely compromised than by any single
route. Attack paths are acyclic source->sink, so full loopy belief propagation / CPTs are
unnecessary: noisy-OR over the enumerated per-sink routes is the correct, ~20-line combination.

# ponytail: noisy-OR over enumerated source->sink routes; no CPT/loopy-BP engine — attack paths
# are acyclic. Upgrade only if cycles ever matter (they don't in this graph).
"""

from __future__ import annotations

from collections.abc import Iterable
from math import prod

from meta_harness.path_priors import DEFAULT_EDGE_PRIOR, EDGE_TRAVERSAL_PRIOR


def route_probability(entry_probability: float, edge_types: Iterable[str]) -> float:
    """P(this one route is walkable end-to-end) = entry leaf-prob x product of per-edge priors."""
    p = entry_probability
    for edge in edge_types:
        p *= EDGE_TRAVERSAL_PRIOR.get(edge, DEFAULT_EDGE_PRIOR)
    return p


def sink_probability(route_probabilities: Iterable[float]) -> float:
    """noisy-OR over every route reaching one sink: 1 - product(1 - p). More routes -> higher P."""
    return 1.0 - prod((1.0 - p) for p in route_probabilities)


__all__ = ["route_probability", "sink_probability"]
