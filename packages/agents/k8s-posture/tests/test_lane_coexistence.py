"""D.6 v0.2 Task 19 — live-lane coexistence (part of Milestone 7).

Proves D.6's `NEXUS_LIVE_K8S_POSTURE` lane gates **independently** of — and never collides
with — every prior live-eval lane (F.3 + D.5 + D.1 + D.2 + D.8 + D.3 + D.4). 16 distinct
gates; enabling one must never enable another.
"""

from __future__ import annotations

import pytest
from k8s_posture.live_lane import nexus_live_k8s_posture_enabled

# Every prior live-eval lane var (F.3 + D.5 + D.1 + D.2 + D.8 + D.3 + D.4).
_PRIOR_LANE_VARS = {
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
    "NEXUS_LIVE_NETWORK_SURICATA",
    "NEXUS_LIVE_NETWORK_ZEEK",
    "NEXUS_LIVE_NETWORK_VPC_AWS",
}
_K8S_LANE_VAR = "NEXUS_LIVE_K8S_POSTURE"
_ALL_LANE_VARS = _PRIOR_LANE_VARS | {_K8S_LANE_VAR}


@pytest.fixture(autouse=True)
def _clear_all_lanes(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_LANE_VARS:
        monkeypatch.delenv(var, raising=False)


def test_all_lane_vars_distinct() -> None:
    # 16 distinct gates: 15 prior + 1 D.6 (single lane, Q2).
    assert len(_ALL_LANE_VARS) == 16
    assert _K8S_LANE_VAR not in _PRIOR_LANE_VARS


def test_k8s_lane_off_by_default() -> None:
    assert nexus_live_k8s_posture_enabled() is False


def test_k8s_lane_responds_only_to_its_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_K8S_LANE_VAR, "1")
    assert nexus_live_k8s_posture_enabled() is True


def test_other_agents_lanes_never_enable_k8s(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _PRIOR_LANE_VARS:
        monkeypatch.setenv(var, "1")
    assert nexus_live_k8s_posture_enabled() is False
