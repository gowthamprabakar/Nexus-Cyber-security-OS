"""D.4 v0.2 Task 18 — AWS VPC flow gated lane tests."""

from __future__ import annotations

import pytest
from network_threat.live_lane import (
    network_vpc_aws_live_skip_reason,
    nexus_live_network_suricata_enabled,
    nexus_live_network_vpc_aws_enabled,
    vpc_aws_reachable,
)


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_NETWORK_VPC_AWS", raising=False)
    monkeypatch.delenv("NEXUS_LIVE_NETWORK_SURICATA", raising=False)


def test_vpc_lane_default_off() -> None:
    assert nexus_live_network_vpc_aws_enabled() is False


def test_vpc_lane_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_VPC_AWS", "1")
    assert nexus_live_network_vpc_aws_enabled() is True


def test_vpc_skip_when_disabled() -> None:
    reason = network_vpc_aws_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_NETWORK_VPC_AWS=1" in reason


def test_vpc_skip_none_when_enabled_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_VPC_AWS", "1")
    assert network_vpc_aws_live_skip_reason(probe=lambda: (True, "")) is None


def test_vpc_skip_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_VPC_AWS", "1")
    reason = network_vpc_aws_live_skip_reason(probe=lambda: (False, "NoCredentialsError"))
    assert reason is not None and "unreachable (NoCredentialsError)" in reason


def test_vpc_reachable_uses_injected_probe() -> None:
    assert vpc_aws_reachable(probe=lambda: (True, "")) == (True, "")


def test_vpc_lane_independent_of_suricata(monkeypatch: pytest.MonkeyPatch) -> None:
    # Q3/Q2: distinct gate — enabling VPC must not enable the Suricata lane.
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_VPC_AWS", "1")
    assert nexus_live_network_vpc_aws_enabled() is True
    assert nexus_live_network_suricata_enabled() is False
