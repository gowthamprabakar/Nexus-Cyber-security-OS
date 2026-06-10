"""Investigation-agent handoff (D.3 v0.2 Task 15).

Per **Q6**, D.3 **emits** a finding with an ``investigation_recommended`` flag (+ an
optional snapshot reference); it does **NOT** auto-escalate. The D.7 Investigation agent
(its Cycle-14 v0.2) consumes the flag and owns escalation. This module only decides the
flag heuristically and attaches it to evidence — there is no escalate/notify surface.

**WI-R5 invariant:** the offline `run()` does not call `attach_investigation_handoff`,
so its findings stay byte-identical; only live findings carry the handoff fields.
"""

from __future__ import annotations

from typing import Any

INVESTIGATION_KEY = "investigation_recommended"
SNAPSHOT_REF_KEY = "snapshot_ref"

#: Severities that warrant a recommendation on their own.
_ESCALATE_SEVERITIES = frozenset({"critical", "high"})

#: A mapped-technique confidence at/above this also warrants a recommendation.
_CONFIDENCE_THRESHOLD = 0.8


def should_recommend_investigation(
    *, severity: str, cross_sensor: bool = False, max_confidence: float = 0.0
) -> bool:
    """Heuristic (Q6): recommend investigation when the finding is high/critical, OR both
    sensors confirmed it, OR a mapped technique is high-confidence."""
    return (
        severity.lower() in _ESCALATE_SEVERITIES
        or cross_sensor
        or max_confidence >= _CONFIDENCE_THRESHOLD
    )


def attach_investigation_handoff(
    evidence: dict[str, Any], *, recommended: bool, snapshot_ref: str | None = None
) -> dict[str, Any]:
    """Return a NEW evidence dict carrying the handoff flag (+ snapshot ref if any).
    D.3 sets the flag; it never escalates. Never mutates the input."""
    out = dict(evidence)
    out[INVESTIGATION_KEY] = recommended
    if snapshot_ref:
        out[SNAPSHOT_REF_KEY] = snapshot_ref
    return out
