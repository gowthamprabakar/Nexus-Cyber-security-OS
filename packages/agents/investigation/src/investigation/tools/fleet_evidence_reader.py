"""Fleet evidence reader (investigation v0.2 Task 2, Q2/WI-I16).

Expands the v0.1 operator-pinned 3-workspace reader to the **13 closed-cycle source agents**
(Q2) — the whole fleet whose findings D.7 collects as evidence. **Additive**: the v0.1
``find_related_findings`` + ``RelatedFinding`` are untouched (the 10 stub eval cases stay
byte-identical, WI-I5), and this reader reuses the same forgiving per-workspace read. Per
**WI-I16 / H6** the read carries a non-empty ``tenant_id`` — every store/workspace access is
tenant-scoped.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from investigation.tools.related_findings import RelatedFinding, _read_one

#: The 13 source agents D.7 collects evidence from (Q2). Unlike D.13, D.7 includes supervisor
#: + synthesis (D.7 investigates supervisor dispatch + D.13 narratives too).
SOURCE_AGENTS: tuple[str, ...] = (
    "cloud_posture",  # F.3
    "multi_cloud_posture",  # D.5
    "vulnerability",  # D.1
    "identity",  # D.2
    "threat_intel",  # D.8
    "runtime_threat",  # D.3
    "network_threat",  # D.4
    "k8s_posture",
    "compliance",
    "data_security",
    "audit",  # F.6
    "supervisor",
    "synthesis",  # D.13
)


class TenantScopeError(ValueError):
    """Raised when a fleet read is attempted without a tenant id (WI-I16/H6)."""


@dataclass(frozen=True, slots=True)
class FleetEvidence:
    tenant_id: str
    by_agent: dict[str, tuple[RelatedFinding, ...]]

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.by_agent.values())

    def agents_with_evidence(self) -> tuple[str, ...]:
        return tuple(a for a in SOURCE_AGENTS if self.by_agent.get(a))

    def for_agent(self, agent_id: str) -> tuple[RelatedFinding, ...]:
        return self.by_agent.get(agent_id, ())


async def read_fleet_evidence(
    workspaces: Mapping[str, Path | None], *, tenant_id: str
) -> FleetEvidence:
    """Read findings.json from each known source agent's workspace concurrently, tenant-scoped.
    Only the 13 ``SOURCE_AGENTS`` are read (an unknown agent id is ignored); a missing workspace
    contributes the empty tuple. Raises ``TenantScopeError`` on an empty ``tenant_id`` (H6)."""
    if not tenant_id:
        raise TenantScopeError("read_fleet_evidence requires a non-empty tenant_id (H6/WI-I16)")
    paths = [workspaces.get(agent) for agent in SOURCE_AGENTS]
    results = await asyncio.gather(
        *(asyncio.to_thread(_read_one, p) if p is not None else _empty() for p in paths)
    )
    return FleetEvidence(
        tenant_id=tenant_id,
        by_agent={agent: tuple(found) for agent, found in zip(SOURCE_AGENTS, results, strict=True)},
    )


async def _empty() -> tuple[RelatedFinding, ...]:
    return ()


__all__ = ["SOURCE_AGENTS", "FleetEvidence", "TenantScopeError", "read_fleet_evidence"]
