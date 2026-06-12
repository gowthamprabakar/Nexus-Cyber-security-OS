"""curiosity v0.2 Task 8 — technique-gap detection (Q4, NEW)."""

from __future__ import annotations

import pytest
from curiosity.gaps.technique import (
    NEVER_SEEN,
    TechniqueGap,
    detect_technique_gaps,
    technique_coverage_gap_id,
)


def test_gap_id_namespace() -> None:
    assert technique_coverage_gap_id("T1078") == "technique:T1078"


def test_never_seen_is_a_gap() -> None:
    gaps = detect_technique_gaps(expected_techniques=["T1078"], last_seen_days={})
    assert gaps == (TechniqueGap("T1078", NEVER_SEEN, "high"),)


def test_stale_beyond_floor_is_a_gap() -> None:
    gaps = detect_technique_gaps(
        expected_techniques=["T1110"], last_seen_days={"T1110": 45}, min_gap_days=30
    )
    assert gaps == (TechniqueGap("T1110", 45, "low"),)


def test_recent_technique_not_a_gap() -> None:
    gaps = detect_technique_gaps(
        expected_techniques=["T1059"], last_seen_days={"T1059": 5}, min_gap_days=30
    )
    assert gaps == ()


def test_severity_buckets() -> None:
    gaps = detect_technique_gaps(
        expected_techniques=["A", "B", "C"],
        last_seen_days={"A": 100, "B": 70, "C": 35},
        min_gap_days=30,
    )
    sev = {g.technique_id: g.severity_hint for g in gaps}
    assert sev == {"A": "high", "B": "medium", "C": "low"}


def test_staleness_first_ordering_never_seen_top() -> None:
    gaps = detect_technique_gaps(
        expected_techniques=["seen", "never"],
        last_seen_days={"seen": 50},
        min_gap_days=30,
    )
    assert [g.technique_id for g in gaps] == ["never", "seen"]


def test_dedup_and_blank_skipped() -> None:
    gaps = detect_technique_gaps(
        expected_techniques=["T1", "T1", ""], last_seen_days={}, min_gap_days=30
    )
    assert [g.technique_id for g in gaps] == ["T1"]


def test_invalid_min_gap_days() -> None:
    with pytest.raises(ValueError, match="min_gap_days"):
        detect_technique_gaps(expected_techniques=["T1"], last_seen_days={}, min_gap_days=0)
