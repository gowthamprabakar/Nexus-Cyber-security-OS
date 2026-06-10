"""D.3 v0.2 Task 17 — NEXUS_LIVE_RUNTIME_TRACEE gated lane tests."""

from __future__ import annotations

import pytest
from runtime_threat.live_lane import (
    nexus_live_runtime_falco_enabled,
    nexus_live_runtime_tracee_enabled,
    runtime_tracee_live_skip_reason,
    tracee_reachable,
)


def test_tracee_lane_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_RUNTIME_TRACEE", raising=False)
    assert nexus_live_runtime_tracee_enabled() is False


def test_tracee_lane_enabled_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_RUNTIME_TRACEE", "1")
    assert nexus_live_runtime_tracee_enabled() is True


def test_skip_reason_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_RUNTIME_TRACEE", raising=False)
    reason = runtime_tracee_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_RUNTIME_TRACEE=1" in reason


def test_skip_reason_none_when_enabled_and_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_RUNTIME_TRACEE", "1")
    assert runtime_tracee_live_skip_reason(probe=lambda: (True, "")) is None


def test_skip_reason_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_RUNTIME_TRACEE", "1")
    reason = runtime_tracee_live_skip_reason(probe=lambda: (False, "pipe-not-found"))
    assert reason is not None and "unreachable (pipe-not-found)" in reason


def test_tracee_reachable_uses_injected_probe() -> None:
    assert tracee_reachable(probe=lambda: (False, "x")) == (False, "x")


def test_tracee_lane_separate_from_falco(monkeypatch: pytest.MonkeyPatch) -> None:
    # Q2: separate gates — enabling Tracee must not enable Falco.
    monkeypatch.delenv("NEXUS_LIVE_RUNTIME_FALCO", raising=False)
    monkeypatch.setenv("NEXUS_LIVE_RUNTIME_TRACEE", "1")
    assert nexus_live_runtime_tracee_enabled() is True
    assert nexus_live_runtime_falco_enabled() is False
