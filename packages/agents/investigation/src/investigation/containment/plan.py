"""Containment plan severity-awareness (investigation v0.2 Task 12, Q5/H4/WI-I14).

D.7 is **advisory** (WI-I14): the PLAN stage emits **recommendations only** — it never enforces.
Per **H4** ("containment first") recommendations are ordered by severity (critical first), and
within a severity, credential rotation before host isolation. The A.1 Remediation handoff is a
**bundle** A.1 may later act on (full auto-dispatch is v0.3, after A.1 v0.2 ships in Cycle 16).
There is deliberately **no enforcement surface** in this module. Pure + deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}

#: H4: within a severity, credential rotation precedes host isolation precedes monitoring.
_ACTION_PRIORITY: dict[str, int] = {
    "rotate_credentials": 2,
    "isolate_host": 1,
    "monitor": 0,
}


@dataclass(frozen=True, slots=True)
class ContainmentRecommendation:
    action_type: str
    target: str
    severity: str
    rationale: str


def order_containment(
    recommendations: Sequence[ContainmentRecommendation],
) -> tuple[ContainmentRecommendation, ...]:
    """Order recommendations: highest severity first, then H4 action priority, then target."""
    return tuple(
        sorted(
            recommendations,
            key=lambda r: (
                -_SEVERITY_RANK.get(r.severity.lower(), 0),
                -_ACTION_PRIORITY.get(r.action_type, 0),
                r.target,
            ),
        )
    )


def build_a1_handoff(
    recommendations: Sequence[ContainmentRecommendation],
) -> dict[str, Any]:
    """The advisory recommendation bundle handed to A.1 Remediation. ADVISORY only — D.7 does
    NOT dispatch or enforce (WI-I14); A.1 auto-dispatch is v0.3."""
    ordered = order_containment(recommendations)
    return {
        "advisory": True,
        "enforced": False,
        "recommendations": [
            {
                "action_type": r.action_type,
                "target": r.target,
                "severity": r.severity,
                "rationale": r.rationale,
            }
            for r in ordered
        ],
    }
