"""D.4 v0.2 Task 17 — Suricata + Zeek gated lane tests."""

from __future__ import annotations

import pytest
from network_threat.live_lane import (
    network_suricata_live_skip_reason,
    network_zeek_live_skip_reason,
    nexus_live_network_suricata_enabled,
    nexus_live_network_zeek_enabled,
    suricata_reachable,
    zeek_reachable,
)


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_NETWORK_SURICATA", raising=False)
    monkeypatch.delenv("NEXUS_LIVE_NETWORK_ZEEK", raising=False)


def test_suricata_lane_default_off() -> None:
    assert nexus_live_network_suricata_enabled() is False


def test_suricata_lane_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_SURICATA", "1")
    assert nexus_live_network_suricata_enabled() is True


def test_suricata_skip_when_disabled() -> None:
    reason = network_suricata_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_NETWORK_SURICATA=1" in reason


def test_suricata_skip_none_when_enabled_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_SURICATA", "1")
    assert network_suricata_live_skip_reason(probe=lambda: (True, "")) is None


def test_suricata_skip_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_SURICATA", "1")
    reason = network_suricata_live_skip_reason(probe=lambda: (False, "socket-not-found"))
    assert reason is not None and "unreachable (socket-not-found)" in reason


def test_zeek_lane_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_ZEEK", "1")
    assert nexus_live_network_zeek_enabled() is True


def test_zeek_skip_when_disabled() -> None:
    reason = network_zeek_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_NETWORK_ZEEK=1" in reason


def test_lanes_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Q2: per-sensor gates — enabling Suricata must not enable Zeek.
    monkeypatch.setenv("NEXUS_LIVE_NETWORK_SURICATA", "1")
    assert nexus_live_network_suricata_enabled() is True
    assert nexus_live_network_zeek_enabled() is False


def test_reachable_helpers_use_injected_probe() -> None:
    assert suricata_reachable(probe=lambda: (True, "")) == (True, "")
    assert zeek_reachable(probe=lambda: (False, "x")) == (False, "x")
