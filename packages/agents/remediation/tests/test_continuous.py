"""remediation v0.2 Task 19 — continuous scheduler + mode coexistence (Q6/WI-A2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from remediation.continuous.mode import (
    DEFAULT_MODE,
    MODE_CONFIG_KEY,
    MonitoringMode,
    modes_coexist,
    select_mode,
    tier_for_mode,
)
from remediation.continuous.scheduler import RemediationScheduler
from remediation.schemas import RemediationMode

_T0 = datetime(2026, 6, 13, tzinfo=UTC)
_TENANT = "cust-1"


def test_never_run_is_due() -> None:
    s = RemediationScheduler()
    s.register(_TENANT, interval_seconds=300)
    assert s.due(_T0) == [_TENANT]
    assert s.next_due_at(_TENANT) is None


def test_not_due_then_due() -> None:
    s = RemediationScheduler()
    s.register(_TENANT, interval_seconds=300)
    s.mark_ran(_TENANT, at=_T0)
    assert s.due(_T0 + timedelta(seconds=100)) == []
    assert s.due(_T0 + timedelta(seconds=300)) == [_TENANT]


def test_empty_tenant_and_interval_rejected() -> None:
    s = RemediationScheduler()
    with pytest.raises(ValueError, match="tenant_id"):
        s.register("", interval_seconds=300)
    with pytest.raises(ValueError, match="positive"):
        s.register(_TENANT, interval_seconds=0)


def test_default_mode_heartbeat() -> None:
    assert DEFAULT_MODE is MonitoringMode.HEARTBEAT
    assert select_mode({}) is MonitoringMode.HEARTBEAT


def test_select_continuous_and_unknown() -> None:
    assert select_mode({MODE_CONFIG_KEY: "continuous"}) is MonitoringMode.CONTINUOUS
    assert select_mode({MODE_CONFIG_KEY: "nope"}) is MonitoringMode.HEARTBEAT
    assert modes_coexist() is True


def test_continuous_preserves_default_recommend() -> None:
    # H1: continuous mode NEVER auto-escalates the tier — both modes default to recommend.
    assert tier_for_mode(MonitoringMode.HEARTBEAT) is RemediationMode.RECOMMEND
    assert tier_for_mode(MonitoringMode.CONTINUOUS) is RemediationMode.RECOMMEND
