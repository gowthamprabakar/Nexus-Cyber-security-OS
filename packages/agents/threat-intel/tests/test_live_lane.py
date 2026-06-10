"""D.8 v0.2 Task 15 — NEXUS_LIVE_THREAT_INTEL gated lane tests."""

from __future__ import annotations

import pytest
from threat_intel.live_lane import (
    FEED_ENDPOINTS,
    feeds_reachable,
    nexus_live_threat_intel_enabled,
    threat_intel_live_skip_reason,
)


def test_lane_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_THREAT_INTEL", raising=False)
    assert nexus_live_threat_intel_enabled() is False


def test_lane_enabled_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_THREAT_INTEL", "1")
    assert nexus_live_threat_intel_enabled() is True


def test_skip_reason_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_THREAT_INTEL", raising=False)
    reason = threat_intel_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_THREAT_INTEL=1" in reason


def test_skip_reason_none_when_enabled_and_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_THREAT_INTEL", "1")
    assert threat_intel_live_skip_reason(probe=lambda: (True, "")) is None


def test_skip_reason_unreachable_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_THREAT_INTEL", "1")
    reason = threat_intel_live_skip_reason(probe=lambda: (False, "nvd:ConnectError"))
    assert reason is not None
    assert "unreachable (nvd:ConnectError)" in reason


def test_feeds_reachable_all_ok() -> None:
    ok, reason = feeds_reachable(probe_one=lambda _url: (True, ""))
    assert ok is True and reason == ""


def test_feeds_reachable_reports_first_failing_feed() -> None:
    def probe(url: str) -> tuple[bool, str]:
        return (False, "ConnectError") if url == FEED_ENDPOINTS["urlhaus"] else (True, "")

    ok, reason = feeds_reachable(probe_one=probe)
    assert ok is False and reason == "urlhaus:ConnectError"


def test_all_seven_feeds_covered() -> None:
    assert set(FEED_ENDPOINTS) == {
        "nvd",
        "kev",
        "mitre",
        "urlhaus",
        "threatfox",
        "malwarebazaar",
        "otx",
    }
