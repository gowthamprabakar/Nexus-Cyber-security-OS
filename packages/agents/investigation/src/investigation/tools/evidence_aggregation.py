"""Multi-source evidence aggregation (investigation v0.2 Task 3, Q2).

Summarizes the fleet evidence read (Task 2) **per source agent** (WI-I1, no aggregate), and
deduplicates findings reported by **multiple** agents for the same incident (a finding uid seen
across sources). Also exposes the **evidence id set** (``finding:<uid>``) that the Task-18
evidence-chain guard checks hypotheses against. Pure + deterministic; envelope fields only.
"""

from __future__ import annotations

from dataclasses import dataclass

from investigation.tools.fleet_evidence_reader import SOURCE_AGENTS, FleetEvidence
from investigation.tools.related_findings import RelatedFinding


@dataclass(frozen=True, slots=True)
class SourceEnumeration:
    agent_id: str
    finding_count: int
    by_class_uid: dict[int, int]
    finding_ids: tuple[str, ...]


def _finding_uid(finding: RelatedFinding) -> str | None:
    info = finding.payload.get("finding_info")
    if isinstance(info, dict):
        uid = info.get("uid")
        if isinstance(uid, str) and uid:
            return uid
    return None


def enumerate_source(agent_id: str, findings: tuple[RelatedFinding, ...]) -> SourceEnumeration:
    by_class: dict[int, int] = {}
    ids: list[str] = []
    for finding in findings:
        by_class[finding.class_uid] = by_class.get(finding.class_uid, 0) + 1
        uid = _finding_uid(finding)
        if uid is not None:
            ids.append(uid)
    return SourceEnumeration(
        agent_id=agent_id,
        finding_count=len(findings),
        by_class_uid=by_class,
        finding_ids=tuple(ids),
    )


def aggregate_fleet(evidence: FleetEvidence) -> tuple[SourceEnumeration, ...]:
    """One enumeration per source agent (WI-I1)."""
    return tuple(enumerate_source(a, evidence.for_agent(a)) for a in SOURCE_AGENTS)


def deduplicate_findings(evidence: FleetEvidence) -> dict[str, tuple[str, ...]]:
    """Map each finding uid -> the sorted agents that reported it. A uid with >1 agent is a
    cross-agent duplicate (the same incident surfaced by several agents)."""
    by_uid: dict[str, set[str]] = {}
    for agent in SOURCE_AGENTS:
        for finding in evidence.for_agent(agent):
            uid = _finding_uid(finding)
            if uid is not None:
                by_uid.setdefault(uid, set()).add(agent)
    return {uid: tuple(sorted(agents)) for uid, agents in by_uid.items()}


def cross_agent_duplicates(evidence: FleetEvidence) -> dict[str, tuple[str, ...]]:
    """Only the finding uids reported by more than one agent."""
    return {
        uid: agents for uid, agents in deduplicate_findings(evidence).items() if len(agents) > 1
    }


def all_evidence_ids(evidence: FleetEvidence) -> set[str]:
    """The ``finding:<uid>`` evidence id set the evidence-chain guard (Task 18) checks against."""
    return {f"finding:{uid}" for uid in deduplicate_findings(evidence)}
