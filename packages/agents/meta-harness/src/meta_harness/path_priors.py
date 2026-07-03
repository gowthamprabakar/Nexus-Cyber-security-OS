"""v0.5 — priors for probabilistic attack-path ranking.

Two prior sources, kept separate by how defensible each is:
- leaf_probability: MEASURED signals. EPSS is a published P(exploit-in-30d); CVSS
  severity + CISA KEV are public. A live EPSS reader (Item 3) can feed here later.
- EDGE_TRAVERSAL_PRIOR: EXPERT priors — hand-chosen P(traverse edge | source owned),
  one source of truth, TUNABLE, never presented as measured.

belief.py composes these; report_card ranks on the result.
"""

from __future__ import annotations

_KEV_FLOOR = 0.9  # CISA KEV = weaponized in the wild -> P floored here via noisy-OR


def leaf_probability(severity_score: int, *, kev: bool = False, epss: float | None = None) -> float:
    """P(the entry exposure is exploited). EPSS wins if present (already a probability);
    else the 0-100 severity maps linearly into [0, 0.8]; KEV floors at 0.9 via noisy-OR."""
    p = float(epss) if epss is not None else max(0, min(100, severity_score)) / 100.0 * 0.8
    if kev:
        p = 1.0 - (1.0 - p) * (1.0 - _KEV_FLOOR)
    return max(0.0, min(1.0, p))


# P(attacker traverses this edge | source already compromised). EXPERT priors, TUNABLE.
# Seeded from path_engine._EDGE_RISK, but these compose as a PRODUCT along a path (each hop an
# independent step), NOT the candidate scorer's weakest-link min. NOT measured — expert judgement.
EDGE_TRAVERSAL_PRIOR: dict[str, float] = {
    "EXPOSES_DATA": 1.0,
    "VULNERABLE_TO": 0.7,
    "RUNS_IMAGE": 0.95,
    "ASSUMES": 0.9,
    "HAS_ACCESS_TO": 0.85,
    "CAN_ESCALATE_TO": 0.9,
    "OWNS": 0.95,
    "OWNED_BY": 0.9,
    "DEFINED_IN": 0.8,
    "CAN_REACH": 0.6,
    "POD_CAN_REACH": 0.6,
    "PEERED_WITH": 0.5,
    "COMMUNICATES_WITH": 0.7,
    "CONTAINS": 0.8,
    "CONTAINS_PACKAGE": 0.4,
    "BINDS": 0.9,
    "EXPOSES_MODEL": 0.9,
    "EXECUTED_ON": 0.95,
    "MATCHES_INDICATOR": 1.0,
    "DEPLOYED_VIA": 0.7,
    "USES_SERVICE_ACCOUNT": 0.8,
    "IRSA_MAPPING": 0.8,
    "STORES_SECRET": 0.7,
}
DEFAULT_EDGE_PRIOR = 0.5  # unknown edge: coin-flip, never a silent 1.0

__all__ = ["DEFAULT_EDGE_PRIOR", "EDGE_TRAVERSAL_PRIOR", "leaf_probability"]
