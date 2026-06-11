"""data-security v0.2 Task 16 — multi-cloud scan scheduler tests (infrastructure only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from data_security.continuous.scheduler import CloudSource, ScanScheduler

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def test_register_per_source() -> None:
    s = ScanScheduler()
    s.register(CloudSource.AWS_S3, interval_seconds=3600)
    s.register(CloudSource.GCS, interval_seconds=600)
    assert set(s.sources()) == {CloudSource.AWS_S3, CloudSource.GCS}


def test_due_when_never_run() -> None:
    s = ScanScheduler()
    s.register(CloudSource.AZURE_BLOB, interval_seconds=3600)
    assert s.due(_T) == [CloudSource.AZURE_BLOB]
    assert s.next_due_at(CloudSource.AZURE_BLOB) is None


def test_not_due_before_interval() -> None:
    s = ScanScheduler()
    s.register(CloudSource.AWS_S3, interval_seconds=3600)
    s.mark_ran(CloudSource.AWS_S3, at=_T)
    assert s.due(_T + timedelta(seconds=1800)) == []


def test_due_after_interval() -> None:
    s = ScanScheduler()
    s.register(CloudSource.AWS_S3, interval_seconds=3600)
    s.mark_ran(CloudSource.AWS_S3, at=_T)
    assert s.due(_T + timedelta(seconds=3600)) == [CloudSource.AWS_S3]


def test_independent_per_source_intervals() -> None:
    s = ScanScheduler()
    s.register(CloudSource.AWS_S3, interval_seconds=3600)
    s.register(CloudSource.GCS, interval_seconds=600)
    s.mark_ran(CloudSource.AWS_S3, at=_T)
    s.mark_ran(CloudSource.GCS, at=_T)
    assert s.due(_T + timedelta(seconds=900)) == [CloudSource.GCS]


def test_next_due_at() -> None:
    s = ScanScheduler()
    s.register(CloudSource.GCS, interval_seconds=600)
    s.mark_ran(CloudSource.GCS, at=_T)
    assert s.next_due_at(CloudSource.GCS) == _T + timedelta(seconds=600)


def test_nonpositive_interval_rejected() -> None:
    with pytest.raises(ValueError, match="positive"):
        ScanScheduler().register(CloudSource.AWS_S3, interval_seconds=0)


def test_mark_ran_unregistered_raises() -> None:
    with pytest.raises(KeyError):
        ScanScheduler().mark_ran(CloudSource.GCS, at=_T)


def test_no_scan_surface() -> None:
    # WI-S11: infrastructure only — no run/scan/start.
    s = ScanScheduler()
    assert not hasattr(s, "run") and not hasattr(s, "scan") and not hasattr(s, "start")
