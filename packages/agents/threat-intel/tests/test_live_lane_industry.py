"""D.8 v0.2 Task 16 — industry-vertical lane (stub) tests."""

from __future__ import annotations

import pytest
from threat_intel.live_lane import (
    INDUSTRY_FEEDS_V0_3,
    industry_feeds_reachable,
    nexus_live_threat_intel_industry_enabled,
    threat_intel_industry_live_skip_reason,
)


def test_industry_lane_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_THREAT_INTEL_INDUSTRY", raising=False)
    assert nexus_live_threat_intel_industry_enabled() is False


def test_industry_lane_enabled_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_THREAT_INTEL_INDUSTRY", "1")
    assert nexus_live_threat_intel_industry_enabled() is True


def test_skip_reason_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_THREAT_INTEL_INDUSTRY", raising=False)
    reason = threat_intel_industry_live_skip_reason()
    assert reason is not None and "NEXUS_LIVE_THREAT_INTEL_INDUSTRY=1" in reason


def test_stub_always_skips_even_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # The v0.2 stub never runs: enabled + the stub probe is unreachable → still a skip.
    monkeypatch.setenv("NEXUS_LIVE_THREAT_INTEL_INDUSTRY", "1")
    reason = threat_intel_industry_live_skip_reason()
    assert reason is not None and "industry-feeds-are-v0.3" in reason


def test_industry_feeds_reachable_is_stub() -> None:
    ok, reason = industry_feeds_reachable()
    assert ok is False and reason == "industry-feeds-are-v0.3"


def test_v0_3_feed_placeholders() -> None:
    assert INDUSTRY_FEEDS_V0_3 == ("wiz-cloud-threat-landscape", "unit42")
