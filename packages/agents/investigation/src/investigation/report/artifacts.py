"""Investigation report artifacts (investigation v0.2 Task 13, WI-I17/WI-I5).

Assembles the operator-readable artifacts that ride **alongside** the unchanged OCSF 2005
IncidentReport (so the wire shape stays byte-identical, WI-I5): the ``plan.md`` markdown from the
advisory containment handoff, and the **cost-telemetry section** (WI-I17) attached additively to
a report dict. Pure + deterministic; the artifacts are additive — no existing schema changed.
"""

from __future__ import annotations

from typing import Any


def render_plan_md(handoff_bundle: dict[str, Any]) -> str:
    """Render the advisory A.1 handoff bundle (Task 12) as ``plan.md`` markdown."""
    lines = ["# Containment Plan (advisory)", ""]
    if not handoff_bundle.get("recommendations"):
        lines.append("_No containment recommendations._")
        return "\n".join(lines) + "\n"
    lines.append("> D.7 is advisory — these are recommendations, not enforced actions (WI-I14).")
    lines.append("")
    for i, rec in enumerate(handoff_bundle["recommendations"], start=1):
        lines.append(
            f"{i}. **{rec['action_type']}** on `{rec['target']}` "
            f"(severity: {rec['severity']}) — {rec['rationale']}"
        )
    return "\n".join(lines) + "\n"


def attach_cost_section(report: dict[str, Any], cost_section: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of an IncidentReport dict with the LLM cost-telemetry section attached
    (WI-I17). Additive — the OCSF 2005 envelope is untouched."""
    return {**report, "llm_cost": dict(cost_section)}
