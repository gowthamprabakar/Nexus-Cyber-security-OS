"""synthesis v0.2 Task 13 — continuous synthesis scheduler tests (Q7/WI-Y2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from synthesis.continuous.scheduler import SynthesisScheduler

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def test_register_per_tenant() -> None:
    s = SynthesisScheduler()
    s.register("c1", interval_seconds=3600)
    s.register("c2", interval_seconds=600)
    assert set(s.tenants()) == {"c1", "c2"}


def test_due_when_never_run() -> None:
    s = SynthesisScheduler()
    s.register("c1", interval_seconds=3600)
    assert s.due(_T) == ["c1"] and s.next_due_at("c1") is None


def test_not_due_before_interval() -> None:
    s = SynthesisScheduler()
    s.register("c1", interval_seconds=3600)
    s.mark_ran("c1", at=_T)
    assert s.due(_T + timedelta(seconds=1800)) == []


def test_due_after_interval() -> None:
    s = SynthesisScheduler()
    s.register("c1", interval_seconds=3600)
    s.mark_ran("c1", at=_T)
    assert s.due(_T + timedelta(seconds=3600)) == ["c1"]


def test_independent_per_tenant_intervals() -> None:
    s = SynthesisScheduler()
    s.register("c1", interval_seconds=3600)
    s.register("c2", interval_seconds=600)
    s.mark_ran("c1", at=_T)
    s.mark_ran("c2", at=_T)
    assert s.due(_T + timedelta(seconds=900)) == ["c2"]


def test_next_due_at() -> None:
    s = SynthesisScheduler()
    s.register("c1", interval_seconds=600)
    s.mark_ran("c1", at=_T)
    assert s.next_due_at("c1") == _T + timedelta(seconds=600)


def test_nonpositive_interval_rejected() -> None:
    with pytest.raises(ValueError, match="positive"):
        SynthesisScheduler().register("c1", interval_seconds=0)


def test_mark_ran_unregistered_raises() -> None:
    with pytest.raises(KeyError):
        SynthesisScheduler().mark_ran("c1", at=_T)


def test_no_run_surface() -> None:
    # WI-Y2: infrastructure only — no run/synthesize/start.
    s = SynthesisScheduler()
    assert not hasattr(s, "run") and not hasattr(s, "synthesize") and not hasattr(s, "start")
