"""D.8 v0.2 Task 18 — live-lane coexistence (closes Milestone 6).

Proves D.8's `NEXUS_LIVE_THREAT_INTEL[_INDUSTRY]` lanes gate **independently** of — and
never collide with — the platform's other live-eval lanes (F.3 `NEXUS_LIVE_AWS`, D.5
`NEXUS_LIVE_AZURE`/`NEXUS_LIVE_GCP`, D.1 `NEXUS_LIVE_REGISTRY_*`, D.2
`NEXUS_LIVE_IDENTITY_*`). Per WI-T1 every lane is its own gate; enabling one must never
enable another — including the prefix-overlapping pair within D.8.
"""

from __future__ import annotations

import pytest
from threat_intel.live_lane import (
    nexus_live_threat_intel_enabled,
    nexus_live_threat_intel_industry_enabled,
)

# Every prior live-eval lane var on the platform, by owning agent (F.3 + D.5 + D.1 + D.2).
_PLATFORM_LANE_VARS = {
    "NEXUS_LIVE_AWS",  # F.3 cloud-posture
    "NEXUS_LIVE_AZURE",  # D.5 multi-cloud-posture
    "NEXUS_LIVE_GCP",  # D.5 multi-cloud-posture
    "NEXUS_LIVE_REGISTRY_AWS",  # D.1 vulnerability
    "NEXUS_LIVE_REGISTRY_AZURE",  # D.1 vulnerability
    "NEXUS_LIVE_REGISTRY_GCP",  # D.1 vulnerability
    "NEXUS_LIVE_IDENTITY_AWS",  # D.2 identity
    "NEXUS_LIVE_IDENTITY_AZURE",  # D.2 identity
}
_THREAT_INTEL_LANE_VARS = {"NEXUS_LIVE_THREAT_INTEL", "NEXUS_LIVE_THREAT_INTEL_INDUSTRY"}
_ALL_LANE_VARS = _PLATFORM_LANE_VARS | _THREAT_INTEL_LANE_VARS


@pytest.fixture(autouse=True)
def _clear_all_lanes(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_LANE_VARS:
        monkeypatch.delenv(var, raising=False)


def test_all_lane_vars_are_distinct() -> None:
    # No two agents share a lane var (10 distinct gates: 8 prior + 2 D.8).
    assert len(_ALL_LANE_VARS) == len(_PLATFORM_LANE_VARS) + len(_THREAT_INTEL_LANE_VARS) == 10
    assert _THREAT_INTEL_LANE_VARS.isdisjoint(_PLATFORM_LANE_VARS)


def test_main_lane_responds_only_to_its_own_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_THREAT_INTEL", "1")
    assert nexus_live_threat_intel_enabled() is True
    assert nexus_live_threat_intel_industry_enabled() is False  # industry lane unaffected


def test_industry_lane_responds_only_to_its_own_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_THREAT_INTEL_INDUSTRY", "1")
    assert nexus_live_threat_intel_industry_enabled() is True
    # Prefix overlap must NOT leak: the main lane stays off.
    assert nexus_live_threat_intel_enabled() is False


def test_other_agents_lanes_never_enable_threat_intel(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _PLATFORM_LANE_VARS:
        monkeypatch.setenv(var, "1")
    assert nexus_live_threat_intel_enabled() is False
    assert nexus_live_threat_intel_industry_enabled() is False


def test_threat_intel_lanes_off_by_default() -> None:
    assert nexus_live_threat_intel_enabled() is False
    assert nexus_live_threat_intel_industry_enabled() is False
