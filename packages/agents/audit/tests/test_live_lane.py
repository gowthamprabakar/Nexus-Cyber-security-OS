"""audit v0.2 Task 15 — NEXUS_LIVE_AUDIT gated lane tests."""

from __future__ import annotations

import pytest
from audit.live_lane import (
    AUDIT_SOURCES,
    audit_live_skip_reason,
    nexus_live_audit_enabled,
    source_reachable,
)


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_AUDIT", raising=False)


def test_lane_default_off() -> None:
    assert nexus_live_audit_enabled() is False


def test_lane_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_AUDIT", "1")
    assert nexus_live_audit_enabled() is True


def test_audit_sources() -> None:
    assert set(AUDIT_SOURCES) == {"charter_jsonl", "f5_episodes", "agent_chain"}


def test_reachable_with_a_source() -> None:
    ok, reason = source_reachable(("f5_episodes",))
    assert ok is True and reason == ""


def test_unreachable_no_source() -> None:
    ok, reason = source_reachable(())
    assert ok is False and reason == "no-audit-source-reachable"


def test_unknown_source_not_counted() -> None:
    ok, _ = source_reachable(("siem",))
    assert ok is False


def test_skip_when_disabled() -> None:
    reason = audit_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_AUDIT=1" in reason


def test_skip_none_when_enabled_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_AUDIT", "1")
    assert audit_live_skip_reason(probe=lambda: (True, "")) is None


def test_skip_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_AUDIT", "1")
    reason = audit_live_skip_reason(probe=lambda: (False, "no-audit-source-reachable"))
    assert reason is not None and "unreachable (no-audit-source-reachable)" in reason
