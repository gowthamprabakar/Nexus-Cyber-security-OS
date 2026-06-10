"""D.3 v0.2 Task 16 — NEXUS_LIVE_RUNTIME_FALCO gated lane tests."""

from __future__ import annotations

import pytest
from runtime_threat.live_lane import (
    falco_reachable,
    nexus_live_runtime_falco_enabled,
    runtime_falco_live_skip_reason,
)


def test_falco_lane_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_RUNTIME_FALCO", raising=False)
    assert nexus_live_runtime_falco_enabled() is False


def test_falco_lane_enabled_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_RUNTIME_FALCO", "1")
    assert nexus_live_runtime_falco_enabled() is True


def test_skip_reason_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_RUNTIME_FALCO", raising=False)
    reason = runtime_falco_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_RUNTIME_FALCO=1" in reason


def test_skip_reason_none_when_enabled_and_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_RUNTIME_FALCO", "1")
    assert runtime_falco_live_skip_reason(probe=lambda: (True, "")) is None


def test_skip_reason_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_RUNTIME_FALCO", "1")
    reason = runtime_falco_live_skip_reason(probe=lambda: (False, "socket-not-found"))
    assert reason is not None and "unreachable (socket-not-found)" in reason


def test_falco_reachable_uses_injected_probe() -> None:
    assert falco_reachable(probe=lambda: (True, "")) == (True, "")
