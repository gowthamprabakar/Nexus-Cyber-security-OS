"""compliance v0.2 Task 20 — live-lane coexistence (part of Milestone 7).

Proves compliance's `NEXUS_LIVE_COMPLIANCE` lane gates **independently** of every prior
live-eval lane (F.3 + D.5 + D.1 + D.2 + D.8 + D.3 + D.4 + k8s-posture). 17 distinct gates;
enabling one must never enable another, and there are no env-var collisions.
"""

from __future__ import annotations

import pytest
from compliance.live_lane import nexus_live_compliance_enabled

# Every prior live-eval lane var (F.3 + D.5 + D.1 + D.2 + D.8 + D.3 + D.4 + k8s-posture).
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
    "NEXUS_LIVE_K8S_POSTURE",
}
_COMPLIANCE_LANE_VAR = "NEXUS_LIVE_COMPLIANCE"
_ALL_LANE_VARS = _PRIOR_LANE_VARS | {_COMPLIANCE_LANE_VAR}


@pytest.fixture(autouse=True)
def _clear_all_lanes(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_LANE_VARS:
        monkeypatch.delenv(var, raising=False)


def test_all_lane_vars_distinct() -> None:
    # 17 distinct gates: 16 prior + 1 compliance.
    assert len(_ALL_LANE_VARS) == 17
    assert _COMPLIANCE_LANE_VAR not in _PRIOR_LANE_VARS


def test_compliance_lane_off_by_default() -> None:
    assert nexus_live_compliance_enabled() is False


def test_compliance_lane_responds_only_to_its_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_COMPLIANCE_LANE_VAR, "1")
    assert nexus_live_compliance_enabled() is True


def test_other_agents_lanes_never_enable_compliance(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _PRIOR_LANE_VARS:
        monkeypatch.setenv(var, "1")
    assert nexus_live_compliance_enabled() is False
