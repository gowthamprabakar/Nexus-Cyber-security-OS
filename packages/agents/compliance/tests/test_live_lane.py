"""compliance v0.2 Task 18 — NEXUS_LIVE_COMPLIANCE gated lane tests."""

from __future__ import annotations

import pytest
from compliance.live_lane import (
    SOURCE_EMITTERS,
    compliance_live_skip_reason,
    emitters_reachable,
    nexus_live_compliance_enabled,
)


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_COMPLIANCE", raising=False)


def test_lane_default_off() -> None:
    assert nexus_live_compliance_enabled() is False


def test_lane_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_COMPLIANCE", "1")
    assert nexus_live_compliance_enabled() is True


def test_source_emitters() -> None:
    assert set(SOURCE_EMITTERS) == {"cloud_posture", "multi_cloud_posture", "k8s_posture"}


def test_reachable_when_an_emitter_present() -> None:
    ok, reason = emitters_reachable(["cloud_posture"])
    assert ok is True and reason == ""


def test_unreachable_when_no_emitter() -> None:
    ok, reason = emitters_reachable([])
    assert ok is False and reason == "no-emitter-reports"


def test_unknown_emitter_not_counted() -> None:
    ok, _ = emitters_reachable(["some_other_agent"])
    assert ok is False


def test_skip_when_disabled() -> None:
    reason = compliance_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_COMPLIANCE=1" in reason


def test_skip_none_when_enabled_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_COMPLIANCE", "1")
    assert compliance_live_skip_reason(probe=lambda: (True, "")) is None


def test_skip_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_COMPLIANCE", "1")
    reason = compliance_live_skip_reason(probe=lambda: (False, "no-emitter-reports"))
    assert reason is not None and "unreachable (no-emitter-reports)" in reason
