"""synthesis v0.2 Task 11 — NEXUS_LIVE_SYNTHESIS gated lane tests (Q6)."""

from __future__ import annotations

import pytest
from synthesis.live_lane import (
    nexus_live_synthesis_enabled,
    provider_reachable,
    synthesis_live_skip_reason,
)


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_SYNTHESIS", raising=False)


def test_lane_default_off() -> None:
    assert nexus_live_synthesis_enabled() is False


def test_lane_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_SYNTHESIS", "1")
    assert nexus_live_synthesis_enabled() is True


def test_provider_reachable_when_configured() -> None:
    ok, reason = provider_reachable(env={"NEXUS_LLM_PROVIDER": "anthropic"})
    assert ok is True and reason == ""


def test_provider_unreachable_when_absent() -> None:
    ok, reason = provider_reachable(env={})
    assert ok is False and reason == "no-llm-provider-configured"


def test_api_key_counts_as_configured() -> None:
    ok, _ = provider_reachable(env={"DEEPSEEK_API_KEY": "sk-x"})
    assert ok is True


def test_skip_when_disabled() -> None:
    reason = synthesis_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_SYNTHESIS=1" in reason


def test_skip_none_when_enabled_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_SYNTHESIS", "1")
    assert synthesis_live_skip_reason(probe=lambda: (True, "")) is None


def test_skip_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_SYNTHESIS", "1")
    reason = synthesis_live_skip_reason(probe=lambda: (False, "no-llm-provider-configured"))
    assert reason is not None and "unreachable (no-llm-provider-configured)" in reason
