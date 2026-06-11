"""data-security v0.2 Task 19 — NEXUS_LIVE_DATA_SECURITY gated lane tests."""

from __future__ import annotations

import pytest
from data_security.live_lane import (
    CLOUD_SOURCES,
    data_security_live_skip_reason,
    nexus_live_data_security_enabled,
    source_reachable,
)


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_LIVE_DATA_SECURITY", raising=False)


def test_lane_default_off() -> None:
    assert nexus_live_data_security_enabled() is False


def test_lane_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_DATA_SECURITY", "1")
    assert nexus_live_data_security_enabled() is True


def test_cloud_sources() -> None:
    assert set(CLOUD_SOURCES) == {"aws_s3", "azure_blob", "gcs"}


def test_reachable_with_a_source() -> None:
    ok, reason = source_reachable(("aws_s3",))
    assert ok is True and reason == ""


def test_unreachable_no_source() -> None:
    ok, reason = source_reachable(())
    assert ok is False and reason == "no-cloud-source-reachable"


def test_unknown_source_not_counted() -> None:
    ok, _ = source_reachable(("rds",))
    assert ok is False


def test_skip_when_disabled() -> None:
    reason = data_security_live_skip_reason(probe=lambda: (True, ""))
    assert reason is not None and "NEXUS_LIVE_DATA_SECURITY=1" in reason


def test_skip_none_when_enabled_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_DATA_SECURITY", "1")
    assert data_security_live_skip_reason(probe=lambda: (True, "")) is None


def test_skip_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_LIVE_DATA_SECURITY", "1")
    reason = data_security_live_skip_reason(probe=lambda: (False, "no-cloud-source-reachable"))
    assert reason is not None and "unreachable (no-cloud-source-reachable)" in reason
