"""investigation v0.2 Task 20 — continuous scheduler tests (WI-I9)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from investigation.continuous.scheduler import InvestigationScheduler

_T0 = datetime(2026, 6, 12, 0, 0, 0, tzinfo=UTC)
_TENANT = "01HZX0000000000000000000AA"


def test_register_and_tenants() -> None:
    s = InvestigationScheduler()
    s.register(_TENANT, interval_seconds=300)
    assert s.tenants() == (_TENANT,)


def test_empty_tenant_rejected() -> None:
    s = InvestigationScheduler()
    with pytest.raises(ValueError, match="tenant_id"):
        s.register("", interval_seconds=300)


def test_nonpositive_interval_rejected() -> None:
    s = InvestigationScheduler()
    with pytest.raises(ValueError, match="positive"):
        s.register(_TENANT, interval_seconds=0)


def test_never_run_is_due() -> None:
    s = InvestigationScheduler()
    s.register(_TENANT, interval_seconds=300)
    assert s.due(_T0) == [_TENANT]
    assert s.next_due_at(_TENANT) is None


def test_not_due_before_interval() -> None:
    s = InvestigationScheduler()
    s.register(_TENANT, interval_seconds=300)
    s.mark_ran(_TENANT, at=_T0)
    assert s.due(_T0 + timedelta(seconds=100)) == []
    assert s.next_due_at(_TENANT) == _T0 + timedelta(seconds=300)


def test_due_after_interval() -> None:
    s = InvestigationScheduler()
    s.register(_TENANT, interval_seconds=300)
    s.mark_ran(_TENANT, at=_T0)
    assert s.due(_T0 + timedelta(seconds=300)) == [_TENANT]


def test_independent_per_tenant_intervals() -> None:
    s = InvestigationScheduler()
    t2 = "01HZX0000000000000000000BB"
    s.register(_TENANT, interval_seconds=300)
    s.register(t2, interval_seconds=60)
    s.mark_ran(_TENANT, at=_T0)
    s.mark_ran(t2, at=_T0)
    # at +120s only the 60s-interval tenant is due.
    assert s.due(_T0 + timedelta(seconds=120)) == [t2]


def test_mark_ran_unregistered_raises() -> None:
    s = InvestigationScheduler()
    with pytest.raises(KeyError, match="not registered"):
        s.mark_ran(_TENANT, at=_T0)
