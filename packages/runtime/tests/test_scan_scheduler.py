"""ScanScheduler — cadence-based due-tenant selection for the scan loop (Task 12)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from nexus_runtime.scan_scheduler import ScanScheduler

_T0 = datetime(2026, 6, 13, tzinfo=UTC)
_1H = timedelta(hours=1)


def test_never_run_tenant_is_due_immediately() -> None:
    sched = ScanScheduler(tenants=["acme"], cadence=_1H)
    assert "acme" in sched.due(_T0)


def test_after_mark_ran_tenant_is_not_due_before_cadence() -> None:
    sched = ScanScheduler(tenants=["acme"], cadence=_1H)
    sched.mark_ran("acme", at=_T0)
    assert sched.due(_T0 + timedelta(minutes=30)) == []


def test_tenant_is_due_again_after_cadence() -> None:
    sched = ScanScheduler(tenants=["acme"], cadence=_1H)
    sched.mark_ran("acme", at=_T0)
    assert "acme" in sched.due(_T0 + timedelta(minutes=61))


def test_boundary_exactly_at_cadence_is_due() -> None:
    """last_ran + cadence <= now — equality makes it due."""
    sched = ScanScheduler(tenants=["acme"], cadence=_1H)
    sched.mark_ran("acme", at=_T0)
    assert "acme" in sched.due(_T0 + _1H)


def test_multiple_tenants_independent() -> None:
    sched = ScanScheduler(tenants=["acme", "beta"], cadence=_1H)
    sched.mark_ran("acme", at=_T0)
    # acme not yet due; beta never ran → still due
    result = sched.due(_T0 + timedelta(minutes=30))
    assert "acme" not in result
    assert "beta" in result


def test_due_order_matches_tenants_order() -> None:
    sched = ScanScheduler(tenants=["a", "b", "c"], cadence=_1H)
    assert sched.due(_T0) == ["a", "b", "c"]
