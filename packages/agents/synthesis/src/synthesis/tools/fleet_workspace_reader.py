"""Fleet workspace reader (synthesis v0.2 Task 5, Q3).

Expands the v0.1 three-source reader to the **12 closed-cycle source agents** (Q3) — the whole
fleet whose findings D.13 narrates. Supervisor (Agent #0) is **not** a source: it emits F.6
audit only, no findings to narrate. This is **additive**: the v0.1 ``read_sibling_workspaces``
+ ``SiblingFindings`` are untouched (the 10 stub eval cases stay byte-identical, WI-Y5), and
this reader reuses the same forgiving per-workspace read. Tenant isolation is the caller's
(each workspace path is already tenant-scoped).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from synthesis.tools.sibling_workspace_reader import _read_one

#: The 12 source agents synthesis narrates (Q3). Supervisor excluded (no findings to narrate).
SOURCE_AGENTS: tuple[str, ...] = (
    "investigation",  # D.7
    "compliance",  # D.6
    "cloud_posture",  # F.3
    "multi_cloud_posture",  # D.5
    "vulnerability",  # D.1
    "identity",  # D.2
    "threat_intel",  # D.8
    "runtime_threat",  # D.3
    "network_threat",  # D.4
    "k8s_posture",
    "data_security",
    "audit",  # F.6
)


@dataclass(frozen=True, slots=True)
class FleetFindings:
    by_agent: dict[str, tuple[dict[str, Any], ...]]

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.by_agent.values())

    def agents_with_findings(self) -> tuple[str, ...]:
        return tuple(a for a in SOURCE_AGENTS if self.by_agent.get(a))

    def for_agent(self, agent_id: str) -> tuple[dict[str, Any], ...]:
        return self.by_agent.get(agent_id, ())


async def read_fleet_workspaces(workspaces: Mapping[str, Path | None]) -> FleetFindings:
    """Read findings.json from each known source agent's workspace concurrently. Only the 12
    ``SOURCE_AGENTS`` are read (an unknown agent id in ``workspaces`` is ignored); a missing or
    skipped workspace contributes the empty tuple."""
    paths = [workspaces.get(agent) for agent in SOURCE_AGENTS]
    results = await asyncio.gather(*(asyncio.to_thread(_read_one, p) for p in paths))
    return FleetFindings(
        by_agent={agent: tuple(found) for agent, found in zip(SOURCE_AGENTS, results, strict=True)}
    )


__all__ = ["SOURCE_AGENTS", "FleetFindings", "read_fleet_workspaces"]
