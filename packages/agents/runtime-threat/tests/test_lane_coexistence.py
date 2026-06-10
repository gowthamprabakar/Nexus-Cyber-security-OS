"""D.3 v0.2 Task 19 — live-lane coexistence (closes Milestone 7).

Proves D.3's `NEXUS_LIVE_RUNTIME_FALCO/TRACEE` lanes gate **independently** of — and
never collide with — the platform's other live-eval lanes (F.3 + D.5 + D.1 + D.2 + D.8).
Per WI-R1 every sensor/lane is its own gate; enabling one must never enable another.
"""

from __future__ import annotations

import pytest
from runtime_threat.live_lane import (
    nexus_live_runtime_falco_enabled,
    nexus_live_runtime_tracee_enabled,
)

# Every prior live-eval lane var on the platform (F.3 + D.5 + D.1 + D.2 + D.8).
_PLATFORM_LANE_VARS = {
    "NEXUS_LIVE_AWS",  # F.3 cloud-posture
    "NEXUS_LIVE_AZURE",  # D.5 multi-cloud-posture
    "NEXUS_LIVE_GCP",  # D.5 multi-cloud-posture
    "NEXUS_LIVE_REGISTRY_AWS",  # D.1 vulnerability
    "NEXUS_LIVE_REGISTRY_AZURE",  # D.1 vulnerability
    "NEXUS_LIVE_REGISTRY_GCP",  # D.1 vulnerability
    "NEXUS_LIVE_IDENTITY_AWS",  # D.2 identity
    "NEXUS_LIVE_IDENTITY_AZURE",  # D.2 identity
    "NEXUS_LIVE_THREAT_INTEL",  # D.8 threat-intel
    "NEXUS_LIVE_THREAT_INTEL_INDUSTRY",  # D.8 threat-intel
}
_RUNTIME_LANE_VARS = {"NEXUS_LIVE_RUNTIME_FALCO", "NEXUS_LIVE_RUNTIME_TRACEE"}
_ALL_LANE_VARS = _PLATFORM_LANE_VARS | _RUNTIME_LANE_VARS


@pytest.fixture(autouse=True)
def _clear_all_lanes(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_LANE_VARS:
        monkeypatch.delenv(var, raising=False)


def test_all_lane_vars_are_distinct() -> None:
    # No two agents share a lane var (12 distinct gates: 10 prior + 2 D.3).
    assert len(_ALL_LANE_VARS) == len(_PLATFORM_LANE_VARS) + len(_RUNTIME_LANE_VARS) == 12
    assert _RUNTIME_LANE_VARS.isdisjoint(_PLATFORM_LANE_VARS)


def test_falco_lane_responds_only_to_its_own_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_RUNTIME_FALCO", "1")
    assert nexus_live_runtime_falco_enabled() is True
    assert nexus_live_runtime_tracee_enabled() is False


def test_tracee_lane_responds_only_to_its_own_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_RUNTIME_TRACEE", "1")
    assert nexus_live_runtime_tracee_enabled() is True
    assert nexus_live_runtime_falco_enabled() is False


def test_other_agents_lanes_never_enable_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _PLATFORM_LANE_VARS:
        monkeypatch.setenv(var, "1")
    assert nexus_live_runtime_falco_enabled() is False
    assert nexus_live_runtime_tracee_enabled() is False


def test_runtime_lanes_off_by_default() -> None:
    assert nexus_live_runtime_falco_enabled() is False
    assert nexus_live_runtime_tracee_enabled() is False
