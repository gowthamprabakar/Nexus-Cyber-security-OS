"""Cross-source narrative orchestration (synthesis v0.2 Task 7, Q3/H3/WI-Y13).

Turns the per-source enumeration (Task 6) into the **cross-source context** the narrator works
from across the 12 sources. Per **H3** it states *risk, then evidence*: each source carries a
quantified severity-weighted risk score + its finding counts, and sources are ranked by risk so
the narrative leads with what matters. The context also carries the **source finding-id set** —
the ground truth the Task-17 hallucination guard (``assert_findings_cited``, WI-Y13) checks the
LLM narrative against. Pure + deterministic; envelope fields only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from synthesis.tools.fleet_enumeration import (
    SourceEnumeration,
    all_cited_finding_ids,
    enumerate_fleet,
)
from synthesis.tools.fleet_workspace_reader import FleetFindings

#: Severity -> risk weight (for the H3 "state risk first" ranking).
_SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "unknown": 0,
}

_TOP_IDS_PER_SOURCE = 5


@dataclass(frozen=True, slots=True)
class SourceRiskSummary:
    agent_id: str
    finding_count: int
    severity_weight: int
    top_finding_ids: tuple[str, ...]


def summarize_source_risk(enumeration: SourceEnumeration) -> SourceRiskSummary:
    """Quantify a source's risk = sum(severity_weight x count) (H3 — risk before evidence)."""
    weight = sum(
        _SEVERITY_WEIGHT.get(sev, 0) * count for sev, count in enumeration.by_severity.items()
    )
    return SourceRiskSummary(
        agent_id=enumeration.agent_id,
        finding_count=enumeration.finding_count,
        severity_weight=weight,
        top_finding_ids=enumeration.finding_ids[:_TOP_IDS_PER_SOURCE],
    )


def rank_sources_by_risk(fleet: FleetFindings) -> tuple[SourceRiskSummary, ...]:
    """Sources with findings, ranked by risk weight desc (agent id breaks ties)."""
    summaries = [summarize_source_risk(e) for e in enumerate_fleet(fleet) if e.finding_count > 0]
    return tuple(sorted(summaries, key=lambda s: (-s.severity_weight, s.agent_id)))


def cross_source_context(fleet: FleetFindings) -> dict[str, Any]:
    """The structured cross-source view fed to the narrator (risk-ranked, quantified, with the
    source finding-id set for the hallucination guard)."""
    ranked = rank_sources_by_risk(fleet)
    return {
        "sources_with_findings": len(ranked),
        "total_findings": fleet.total,
        "ranked_sources": [
            {
                "agent": s.agent_id,
                "count": s.finding_count,
                "risk_weight": s.severity_weight,
                "top_ids": list(s.top_finding_ids),
            }
            for s in ranked
        ],
        "source_finding_id_set": sorted(all_cited_finding_ids(fleet)),
    }
