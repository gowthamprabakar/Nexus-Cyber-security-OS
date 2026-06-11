"""Cross-agent audit chain enumerator (audit v0.2 Task 2, Q1).

Discovers the audit chains F.6 can query — per **Q1**: charter ``audit.jsonl`` files, F.5
episode chains, and the per-agent chains of the **10 closed-cycle agents**. Enumeration is
read-only metadata only (no chain content); per **WI-F1** sources are grouped by source type
so coverage is measured per-source, not as an aggregate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

#: The 10 closed-cycle agents whose audit chains are queryable through F.6 at v0.2 (Q1).
AUDITED_AGENTS: tuple[str, ...] = (
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
)


class SourceType(StrEnum):
    CHARTER_JSONL = "charter_jsonl"
    F5_EPISODES = "f5_episodes"
    AGENT_CHAIN = "agent_chain"


@dataclass(frozen=True, slots=True)
class ChainSource:
    source_type: SourceType
    agent_id: str  # "" for an aggregate charter source, else the owning agent
    location: str  # a path or a table reference — metadata only


def enumerate_chains(
    *,
    charter_jsonl: Sequence[str] = (),
    f5_episode_agents: Sequence[str] = (),
    agent_chains: Mapping[str, str] | None = None,
) -> tuple[ChainSource, ...]:
    """Enumerate available audit chains across the three Q1 source kinds. Unknown agent ids
    (not in `AUDITED_AGENTS`) are skipped — F.6 enumerates the closed-cycle agents."""
    out: list[ChainSource] = []
    for path in charter_jsonl:
        out.append(ChainSource(SourceType.CHARTER_JSONL, "", path))
    for agent in f5_episode_agents:
        if agent in AUDITED_AGENTS:
            out.append(ChainSource(SourceType.F5_EPISODES, agent, f"episodes:{agent}"))
    for agent, location in (agent_chains or {}).items():
        if agent in AUDITED_AGENTS:
            out.append(ChainSource(SourceType.AGENT_CHAIN, agent, location))
    return tuple(out)


def by_source_type(
    sources: Sequence[ChainSource],
) -> dict[SourceType, tuple[ChainSource, ...]]:
    """Group enumerated chains by source type (WI-F1 — per-source coverage, no aggregate)."""
    out: dict[SourceType, list[ChainSource]] = {}
    for s in sources:
        out.setdefault(s.source_type, []).append(s)
    return {k: tuple(v) for k, v in out.items()}
