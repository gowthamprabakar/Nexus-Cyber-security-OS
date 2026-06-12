"""curiosity v0.2 Task 18 — continuous scheduler + mode coexistence (Q6/WI-X2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from curiosity.continuous.mode import (
    DEFAULT_MODE,
    MODE_CONFIG_KEY,
    MonitoringMode,
    emit_for_mode,
    modes_coexist,
    select_mode,
)
from curiosity.continuous.scheduler import CuriosityScheduler
from curiosity.schemas import CuriosityReport

_T0 = datetime(2026, 6, 13, tzinfo=UTC)
_TENANT = "01HV0T0000000000000000TENA"


def _report() -> CuriosityReport:
    return CuriosityReport(
        customer_id="c1", run_id="r1", scan_started_at=_T0, scan_completed_at=_T0
    )


def test_never_run_is_due() -> None:
    s = CuriosityScheduler()
    s.register(_TENANT, interval_seconds=300)
    assert s.due(_T0) == [_TENANT]
    assert s.next_due_at(_TENANT) is None


def test_not_due_then_due() -> None:
    s = CuriosityScheduler()
    s.register(_TENANT, interval_seconds=300)
    s.mark_ran(_TENANT, at=_T0)
    assert s.due(_T0 + timedelta(seconds=100)) == []
    assert s.due(_T0 + timedelta(seconds=300)) == [_TENANT]


def test_empty_tenant_and_interval_rejected() -> None:
    s = CuriosityScheduler()
    with pytest.raises(ValueError, match="tenant_id"):
        s.register("", interval_seconds=300)
    with pytest.raises(ValueError, match="positive"):
        s.register(_TENANT, interval_seconds=0)


def test_independent_intervals() -> None:
    s = CuriosityScheduler()
    t2 = "01HV0T0000000000000000TENB"
    s.register(_TENANT, interval_seconds=300)
    s.register(t2, interval_seconds=60)
    s.mark_ran(_TENANT, at=_T0)
    s.mark_ran(t2, at=_T0)
    assert s.due(_T0 + timedelta(seconds=120)) == [t2]


def test_default_mode_heartbeat() -> None:
    assert DEFAULT_MODE is MonitoringMode.HEARTBEAT
    assert select_mode({}) is MonitoringMode.HEARTBEAT


def test_select_continuous_and_unknown() -> None:
    assert select_mode({MODE_CONFIG_KEY: "continuous"}) is MonitoringMode.CONTINUOUS
    assert select_mode({MODE_CONFIG_KEY: "nope"}) is MonitoringMode.HEARTBEAT
    assert modes_coexist() is True


def test_emit_is_mode_independent() -> None:
    report = _report()
    assert emit_for_mode(MonitoringMode.HEARTBEAT, report) == emit_for_mode(
        MonitoringMode.CONTINUOUS, report
    )
