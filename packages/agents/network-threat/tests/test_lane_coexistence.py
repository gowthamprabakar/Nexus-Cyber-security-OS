"""D.4 v0.2 Task 19 — live-lane coexistence (part of Milestone 7).

Proves D.4's `NEXUS_LIVE_NETWORK_*` lanes gate **independently** of — and never collide
with — every prior live-eval lane (F.3 + D.5 + D.1 + D.2 + D.8 + D.3). Per WI-N1 every
sensor/lane is its own gate; enabling one must never enable another.
"""

from __future__ import annotations

import pytest
from network_threat.live_lane import (
    nexus_live_network_suricata_enabled,
    nexus_live_network_vpc_aws_enabled,
    nexus_live_network_zeek_enabled,
)

# Every prior live-eval lane var (F.3 + D.5 + D.1 + D.2 + D.8 + D.3).
_PLATFORM_LANE_VARS = {
    "NEXUS_LIVE_AWS",
    "NEXUS_LIVE_AZURE",
    "NEXUS_LIVE_GCP",
    "NEXUS_LIVE_REGISTRY_AWS",
    "NEXUS_LIVE_REGISTRY_AZURE",
    "NEXUS_LIVE_REGISTRY_GCP",
    "NEXUS_LIVE_IDENTITY_AWS",
    "NEXUS_LIVE_IDENTITY_AZURE",
    "NEXUS_LIVE_THREAT_INTEL",
    "NEXUS_LIVE_THREAT_INTEL_INDUSTRY",
    "NEXUS_LIVE_RUNTIME_FALCO",
    "NEXUS_LIVE_RUNTIME_TRACEE",
}
_NETWORK_LANE_VARS = {
    "NEXUS_LIVE_NETWORK_SURICATA",
    "NEXUS_LIVE_NETWORK_ZEEK",
    "NEXUS_LIVE_NETWORK_VPC_AWS",
}
_ALL_LANE_VARS = _PLATFORM_LANE_VARS | _NETWORK_LANE_VARS


@pytest.fixture(autouse=True)
def _clear_all_lanes(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_LANE_VARS:
        monkeypatch.delenv(var, raising=False)


def test_all_lane_vars_are_distinct() -> None:
    # No two agents share a lane var (15 distinct gates: 12 prior + 3 D.4).
    assert len(_ALL_LANE_VARS) == len(_PLATFORM_LANE_VARS) + len(_NETWORK_LANE_VARS) == 15
    assert _NETWORK_LANE_VARS.isdisjoint(_PLATFORM_LANE_VARS)


def test_suricata_lane_responds_only_to_its_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_SURICATA", "1")
    assert nexus_live_network_suricata_enabled() is True
    assert nexus_live_network_zeek_enabled() is False
    assert nexus_live_network_vpc_aws_enabled() is False


def test_vpc_lane_responds_only_to_its_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_VPC_AWS", "1")
    assert nexus_live_network_vpc_aws_enabled() is True
    assert nexus_live_network_suricata_enabled() is False


def test_other_agents_lanes_never_enable_network(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _PLATFORM_LANE_VARS:
        monkeypatch.setenv(var, "1")
    assert nexus_live_network_suricata_enabled() is False
    assert nexus_live_network_zeek_enabled() is False
    assert nexus_live_network_vpc_aws_enabled() is False


def test_network_lanes_off_by_default() -> None:
    assert nexus_live_network_suricata_enabled() is False
    assert nexus_live_network_zeek_enabled() is False
    assert nexus_live_network_vpc_aws_enabled() is False
