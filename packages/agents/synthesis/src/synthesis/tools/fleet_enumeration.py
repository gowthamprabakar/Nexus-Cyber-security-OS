"""Per-source finding enumeration (synthesis v0.2 Task 6, Q3/WI-Y1).

Summarizes the fleet read (Task 5) **per source agent**: finding count, breakdown by OCSF
class_uid + severity, and the set of finding ids. Per **WI-Y1** coverage is tracked per-source,
never as a fleet aggregate — so honest per-source reporting is possible at closure. Pure +
deterministic; reads only OCSF envelope fields (never plaintext bodies).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from synthesis.tools.fleet_workspace_reader import SOURCE_AGENTS, FleetFindings


@dataclass(frozen=True, slots=True)
class SourceEnumeration:
    agent_id: str
    finding_count: int
    by_class_uid: dict[int, int]
    by_severity: dict[str, int]
    finding_ids: tuple[str, ...]


def _finding_id(finding: dict[str, Any]) -> str | None:
    info = finding.get("finding_info")
    if isinstance(info, dict):
        uid = info.get("uid")
        if isinstance(uid, str) and uid:
            return uid
    return None


def _severity_label(finding: dict[str, Any]) -> str:
    severity = finding.get("severity")
    if isinstance(severity, str) and severity:
        return severity.lower()
    return "unknown"


def enumerate_source(agent_id: str, findings: tuple[dict[str, Any], ...]) -> SourceEnumeration:
    """Enumerate one source agent's findings."""
    by_class: dict[int, int] = {}
    by_sev: dict[str, int] = {}
    ids: list[str] = []
    for finding in findings:
        class_uid = finding.get("class_uid")
        if isinstance(class_uid, int):
            by_class[class_uid] = by_class.get(class_uid, 0) + 1
        sev = _severity_label(finding)
        by_sev[sev] = by_sev.get(sev, 0) + 1
        fid = _finding_id(finding)
        if fid is not None:
            ids.append(fid)
    return SourceEnumeration(
        agent_id=agent_id,
        finding_count=len(findings),
        by_class_uid=by_class,
        by_severity=by_sev,
        finding_ids=tuple(ids),
    )


def enumerate_fleet(fleet: FleetFindings) -> tuple[SourceEnumeration, ...]:
    """Enumerate every source agent (one entry per source, WI-Y1 — no aggregate)."""
    return tuple(enumerate_source(agent, fleet.for_agent(agent)) for agent in SOURCE_AGENTS)


def all_cited_finding_ids(fleet: FleetFindings) -> set[str]:
    """The union of every source's finding ids — the source set the hallucination guard
    (Task 17) checks the narrative against."""
    out: set[str] = set()
    for agent in SOURCE_AGENTS:
        out.update(enumerate_source(agent, fleet.for_agent(agent)).finding_ids)
    return out
