"""supervisor v0.2 Task 2 — live agent registry tests (Q1)."""

from __future__ import annotations

import pytest
from supervisor.routing.live_registry import (
    V0_1_AGENTS,
    V0_2_AGENTS,
    AgentEntry,
    DispatchMode,
    dispatch_mode,
    known_agents,
    live_registry,
    validate_routing_targets,
)


def test_eleven_v0_2_agents() -> None:
    assert len(V0_2_AGENTS) == 11
    assert {"cloud_posture", "compliance", "data_security", "audit"} <= set(V0_2_AGENTS)


def test_v0_2_agents_get_full_dispatch() -> None:
    for a in V0_2_AGENTS:
        assert dispatch_mode(a) == DispatchMode.FULL


def test_v0_1_agents_get_basic_dispatch() -> None:
    for a in V0_1_AGENTS:
        assert dispatch_mode(a) == DispatchMode.BASIC


def test_supervisor_not_in_registry() -> None:
    # Supervisor does not dispatch to itself.
    assert "supervisor" not in known_agents()


def test_registry_entries() -> None:
    reg = live_registry()
    assert len(reg) == len(V0_2_AGENTS) + len(V0_1_AGENTS)
    assert AgentEntry("audit", DispatchMode.FULL) in reg


def test_unknown_agent_dispatch_mode_raises() -> None:
    with pytest.raises(KeyError):
        dispatch_mode("ghost")


def test_validate_routing_targets_all_known() -> None:
    assert validate_routing_targets(frozenset({"compliance", "audit"})) == frozenset()


def test_validate_routing_targets_escalate_ok() -> None:
    # escalate is a valid pseudo-target.
    assert validate_routing_targets(frozenset({"escalate"})) == frozenset()


def test_validate_routing_targets_flags_unknown() -> None:
    assert validate_routing_targets(frozenset({"compliance", "ghost"})) == frozenset({"ghost"})


def test_known_agents_count() -> None:
    assert len(known_agents()) == len(V0_2_AGENTS) + len(V0_1_AGENTS)
