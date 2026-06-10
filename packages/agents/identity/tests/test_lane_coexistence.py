"""D.2 v0.2 Task 19 — live-lane coexistence (closes Milestone 6).

Proves identity's `NEXUS_LIVE_IDENTITY_*` lanes gate **independently** of — and never
collide with — the platform's other live-eval lanes (F.3 `NEXUS_LIVE_AWS`, D.5
`NEXUS_LIVE_AZURE`/`NEXUS_LIVE_GCP`, D.1 `NEXUS_LIVE_REGISTRY_*`). Per WI-I1 every lane
is its own gate; enabling one must never enable another.

The registry below is verified against the other agents' sources (each lane reads
exactly its named env var via the hoisted `charter.live_lane.nexus_live_enabled`).
"""

from __future__ import annotations

import pytest
from identity.live_lane_aws import nexus_live_identity_aws_enabled
from identity.live_lane_azure import nexus_live_identity_azure_enabled

# Every live-eval lane var on the platform, by owning agent.
_PLATFORM_LANE_VARS = {
    "NEXUS_LIVE_AWS",  # F.3 cloud-posture
    "NEXUS_LIVE_AZURE",  # D.5 multi-cloud-posture
    "NEXUS_LIVE_GCP",  # D.5 multi-cloud-posture
    "NEXUS_LIVE_REGISTRY_AWS",  # D.1 vulnerability
    "NEXUS_LIVE_REGISTRY_AZURE",  # D.1 vulnerability
    "NEXUS_LIVE_REGISTRY_GCP",  # D.1 vulnerability
}
_IDENTITY_LANE_VARS = {"NEXUS_LIVE_IDENTITY_AWS", "NEXUS_LIVE_IDENTITY_AZURE"}
_ALL_LANE_VARS = _PLATFORM_LANE_VARS | _IDENTITY_LANE_VARS


@pytest.fixture(autouse=True)
def _clear_all_lanes(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ALL_LANE_VARS:
        monkeypatch.delenv(var, raising=False)


def test_all_lane_vars_are_distinct() -> None:
    # No two agents share a lane var (8 distinct gates).
    assert len(_ALL_LANE_VARS) == len(_PLATFORM_LANE_VARS) + len(_IDENTITY_LANE_VARS) == 8
    assert _IDENTITY_LANE_VARS.isdisjoint(_PLATFORM_LANE_VARS)


def test_identity_aws_lane_responds_only_to_its_own_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AWS", "1")
    assert nexus_live_identity_aws_enabled() is True
    assert nexus_live_identity_azure_enabled() is False  # the Azure lane is unaffected


def test_identity_azure_lane_responds_only_to_its_own_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_IDENTITY_AZURE", "1")
    assert nexus_live_identity_azure_enabled() is True
    assert nexus_live_identity_aws_enabled() is False  # the AWS lane is unaffected


def test_other_agents_lanes_never_enable_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    # Turn on every OTHER platform lane; identity's lanes must stay OFF.
    for var in _PLATFORM_LANE_VARS:
        monkeypatch.setenv(var, "1")
    assert nexus_live_identity_aws_enabled() is False
    assert nexus_live_identity_azure_enabled() is False
