"""compliance v0.2 Task 12 — background scan scheduler tests (infrastructure only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from compliance.continuous.scheduler import ScanScheduler

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def test_register_and_frameworks() -> None:
    s = ScanScheduler()
    s.register("cis_aws_v3", interval_seconds=3600)
    assert s.frameworks() == ("cis_aws_v3",)


def test_due_when_never_run() -> None:
    s = ScanScheduler()
    s.register("cis_aws_v3", interval_seconds=3600)
    assert s.due(_T) == ["cis_aws_v3"]  # never run -> always due
    assert s.next_due_at("cis_aws_v3") is None


def test_not_due_before_interval() -> None:
    s = ScanScheduler()
    s.register("cis_aws_v3", interval_seconds=3600)
    s.mark_ran("cis_aws_v3", at=_T)
    assert s.due(_T + timedelta(seconds=1800)) == []  # half an interval -> not due


def test_due_after_interval() -> None:
    s = ScanScheduler()
    s.register("cis_aws_v3", interval_seconds=3600)
    s.mark_ran("cis_aws_v3", at=_T)
    assert s.due(_T + timedelta(seconds=3600)) == ["cis_aws_v3"]


def test_next_due_at_after_run() -> None:
    s = ScanScheduler()
    s.register("cis_aws_v3", interval_seconds=3600)
    s.mark_ran("cis_aws_v3", at=_T)
    assert s.next_due_at("cis_aws_v3") == _T + timedelta(seconds=3600)


def test_multiple_frameworks_independent_intervals() -> None:
    s = ScanScheduler()
    s.register("cis_aws_v3", interval_seconds=3600)
    s.register("cis_k8s_v18", interval_seconds=600)
    s.mark_ran("cis_aws_v3", at=_T)
    s.mark_ran("cis_k8s_v18", at=_T)
    due = s.due(_T + timedelta(seconds=900))  # k8s due (600), aws not (3600)
    assert due == ["cis_k8s_v18"]


def test_register_rejects_nonpositive_interval() -> None:
    with pytest.raises(ValueError, match="positive"):
        ScanScheduler().register("f", interval_seconds=0)


def test_mark_ran_unregistered_raises() -> None:
    with pytest.raises(KeyError):
        ScanScheduler().mark_ran("nope", at=_T)


def test_scheduler_does_not_run_scans() -> None:
    # WI-C4 / pause-trigger #11: the scheduler is infrastructure only — no run()/scan surface.
    s = ScanScheduler()
    assert not hasattr(s, "run") and not hasattr(s, "scan") and not hasattr(s, "start")
