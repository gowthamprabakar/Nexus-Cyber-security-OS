"""D.6 v0.2 Task 17 — NEXUS_LIVE_K8S_POSTURE gated lane tests."""

from __future__ import annotations

import pytest
from k8s_posture.live_lane import (
    k8s_posture_live_skip_reason,
    k8s_reachable,
    nexus_live_k8s_posture_enabled,
)


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_K8S_POSTURE", raising=False)


def test_lane_default_off() -> None:
    assert nexus_live_k8s_posture_enabled() is False


def test_lane_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_K8S_POSTURE", "1")
    assert nexus_live_k8s_posture_enabled() is True


def test_skip_when_disabled() -> None:
    reason = k8s_posture_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_K8S_POSTURE=1" in reason


def test_skip_none_when_enabled_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_K8S_POSTURE", "1")
    assert k8s_posture_live_skip_reason(probe=lambda: (True, "")) is None


def test_skip_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_K8S_POSTURE", "1")
    reason = k8s_posture_live_skip_reason(probe=lambda: (False, "kubeconfig-not-found"))
    assert reason is not None and "unreachable (kubeconfig-not-found)" in reason


def test_reachable_uses_injected_probe() -> None:
    assert k8s_reachable(probe=lambda: (True, "")) == (True, "")


def test_probe_reports_unset_kubeconfig(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KUBECONFIG", raising=False)
    ok, reason = k8s_reachable()
    assert ok is False and reason == "KUBECONFIG-unset"
