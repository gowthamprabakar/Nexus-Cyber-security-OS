"""curiosity v0.2 Task 9 — time-gap detection (Q4, NEW)."""

from __future__ import annotations

import pytest
from curiosity.gaps.time_gap import (
    NEVER_SCANNED,
    TimeGap,
    detect_time_gaps,
    time_coverage_gap_id,
)


def test_gap_id_namespace() -> None:
    assert time_coverage_gap_id("ec2") == "time:ec2"


def test_never_scanned_is_a_gap() -> None:
    gaps = detect_time_gaps(asset_classes=["lambda"], last_scan_hours={})
    assert gaps == (TimeGap("lambda", NEVER_SCANNED, "high"),)


def test_stale_beyond_floor_is_a_gap() -> None:
    gaps = detect_time_gaps(asset_classes=["s3"], last_scan_hours={"s3": 30}, min_gap_hours=24)
    assert gaps == (TimeGap("s3", 30, "low"),)


def test_recent_scan_not_a_gap() -> None:
    gaps = detect_time_gaps(asset_classes=["rds"], last_scan_hours={"rds": 2}, min_gap_hours=24)
    assert gaps == ()


def test_severity_buckets() -> None:
    gaps = detect_time_gaps(
        asset_classes=["a", "b", "c"],
        last_scan_hours={"a": 200, "b": 80, "c": 30},
        min_gap_hours=24,
    )
    sev = {g.asset_class: g.severity_hint for g in gaps}
    assert sev == {"a": "high", "b": "medium", "c": "low"}


def test_staleness_first_never_scanned_top() -> None:
    gaps = detect_time_gaps(
        asset_classes=["seen", "never"], last_scan_hours={"seen": 100}, min_gap_hours=24
    )
    assert [g.asset_class for g in gaps] == ["never", "seen"]


def test_dedup_and_blank_skipped() -> None:
    gaps = detect_time_gaps(asset_classes=["ec2", "ec2", ""], last_scan_hours={}, min_gap_hours=24)
    assert [g.asset_class for g in gaps] == ["ec2"]


def test_invalid_min_gap_hours() -> None:
    with pytest.raises(ValueError, match="min_gap_hours"):
        detect_time_gaps(asset_classes=["ec2"], last_scan_hours={}, min_gap_hours=0)
