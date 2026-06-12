"""Live agent registry (supervisor v0.2 Task 2, Q1).

The canonical set of agents the supervisor can dispatch to, and at what fidelity. Per **Q1**,
the **11 closed-cycle v0.2 agents** get **full** dispatch; the remaining built v0.1 agents get
**basic** dispatch until they reach v0.2. Routing rules are validated against this registry so
a rule can never target an unknown agent. Pure + declarative — this is registry data, not a
tool (the dispatcher-class deviation holds, WI-O11).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DispatchMode(StrEnum):
    FULL = "full"  # v0.2 agents — full live dispatch
    BASIC = "basic"  # v0.1 agents — basic dispatch until they reach v0.2


#: The 11 closed-cycle v0.2 agents (Q1) — full dispatch scope.
V0_2_AGENTS: tuple[str, ...] = (
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
)

#: The remaining built agents — basic dispatch until their own v0.2 cycle (supervisor excluded;
#: it does not dispatch to itself).
V0_1_AGENTS: tuple[str, ...] = (
    "synthesis",
    "investigation",
    "curiosity",
    "remediation",
    "meta_harness",
)

#: Non-agent routing outcomes that are always valid targets.
PSEUDO_TARGETS: frozenset[str] = frozenset({"escalate"})


@dataclass(frozen=True, slots=True)
class AgentEntry:
    agent_id: str
    dispatch_mode: DispatchMode


def live_registry() -> tuple[AgentEntry, ...]:
    """The full registry — v0.2 agents (full) followed by v0.1 agents (basic)."""
    return tuple(AgentEntry(a, DispatchMode.FULL) for a in V0_2_AGENTS) + tuple(
        AgentEntry(a, DispatchMode.BASIC) for a in V0_1_AGENTS
    )


def known_agents() -> frozenset[str]:
    """The set of all dispatchable agent ids (v0.2 + v0.1)."""
    return frozenset(V0_2_AGENTS) | frozenset(V0_1_AGENTS)


def dispatch_mode(agent_id: str) -> DispatchMode:
    """The dispatch fidelity for ``agent_id`` (raises ``KeyError`` if unknown)."""
    if agent_id in V0_2_AGENTS:
        return DispatchMode.FULL
    if agent_id in V0_1_AGENTS:
        return DispatchMode.BASIC
    raise KeyError(f"unknown agent: {agent_id!r}")


def validate_routing_targets(targets: frozenset[str]) -> frozenset[str]:
    """Return the targets that are **not** valid (unknown agents). A pseudo-target like
    ``escalate`` is always valid; an empty return means every target is routable."""
    valid = known_agents() | PSEUDO_TARGETS
    return frozenset(targets) - valid
