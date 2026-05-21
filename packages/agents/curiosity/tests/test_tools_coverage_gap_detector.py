"""Tests — `curiosity.tools.coverage_gap_detector` (Task 4).

Validates the deterministic region-gap detector. v0.1 ships ONE
detector; multiple gap-shape detectors are deferred to v0.2.

14 tests covering:

1-2. Threshold floor (≥10 asset_count cutoff).
3-4. Threshold floor (≥30 days gap cutoff) + ever-scanned/never-
     scanned distinction.
5. Severity hint bucketing (high / medium / low).
6. Asset-count descending sort.
7-8. Empty SiblingState + no-qualifying-regions.
9. Negative min_asset_count rejected.
10. Custom thresholds.
11. Region-name tie-break (alphabetical).
12. days_since_last_finding=-1 (never scanned) always qualifies.
13. Output is a tuple (frozen, hashable).
14. CoverageGap days_since normalized (no negative values in output).
"""

from __future__ import annotations

import pytest
from curiosity.tools.coverage_gap_detector import detect_coverage_gaps
from curiosity.tools.sibling_state_reader import RegionState, SiblingState


def _region(
    region: str,
    *,
    asset_count: int = 50,
    days: int = 60,
    severity: str | None = "medium",
) -> RegionState:
    return RegionState(
        region=region,
        asset_count=asset_count,
        days_since_last_finding=days,
        last_finding_severity=severity,
    )


def _state(*regions: RegionState) -> SiblingState:
    return SiblingState(
        regions=tuple(regions),
        total_assets=sum(r.asset_count for r in regions),
        total_findings_30d=0,
    )


# ---------------------------------------------------------------------------
# Asset-count threshold
# ---------------------------------------------------------------------------


def test_region_below_asset_threshold_is_skipped() -> None:
    """asset_count < 10 -> not a gap, regardless of finding gap."""
    state = _state(_region("us-east-1", asset_count=5, days=999))
    assert detect_coverage_gaps(state) == ()


def test_region_at_threshold_qualifies() -> None:
    """asset_count == 10 + 30+ day gap -> qualifies."""
    state = _state(_region("us-east-1", asset_count=10, days=45))
    gaps = detect_coverage_gaps(state)
    assert len(gaps) == 1
    assert gaps[0].region == "us-east-1"


# ---------------------------------------------------------------------------
# Day-gap threshold
# ---------------------------------------------------------------------------


def test_recent_finding_does_not_qualify() -> None:
    """asset_count >= 10 + days < 30 -> not a gap."""
    state = _state(_region("us-east-1", asset_count=20, days=15))
    assert detect_coverage_gaps(state) == ()


def test_never_scanned_region_always_qualifies() -> None:
    """days_since_last_finding == -1 (sentinel) -> always a gap
    when asset_count threshold is met."""
    state = _state(_region("ap-south-1", asset_count=12, days=-1))
    gaps = detect_coverage_gaps(state)
    assert len(gaps) == 1
    assert gaps[0].region == "ap-south-1"


# ---------------------------------------------------------------------------
# Severity hint bucketing
# ---------------------------------------------------------------------------


def test_severity_hint_buckets() -> None:
    state = _state(
        _region("low-region", asset_count=12, days=40),
        _region("medium-region", asset_count=50, days=40),
        _region("high-region", asset_count=200, days=40),
    )
    gaps = detect_coverage_gaps(state)
    by_region = {g.region: g.severity_hint for g in gaps}
    assert by_region["low-region"] == "low"
    assert by_region["medium-region"] == "medium"
    assert by_region["high-region"] == "high"


# ---------------------------------------------------------------------------
# Ordering — biggest blast-radius first
# ---------------------------------------------------------------------------


def test_gaps_ordered_by_asset_count_descending() -> None:
    state = _state(
        _region("small-region", asset_count=15, days=60),
        _region("big-region", asset_count=150, days=60),
        _region("medium-region", asset_count=50, days=60),
    )
    gaps = detect_coverage_gaps(state)
    asset_counts = [g.asset_count for g in gaps]
    assert asset_counts == [150, 50, 15]


def test_same_asset_count_breaks_tie_alphabetically() -> None:
    """Two regions with identical asset counts -> sorted by region name."""
    state = _state(
        _region("z-region", asset_count=50, days=60),
        _region("a-region", asset_count=50, days=60),
        _region("m-region", asset_count=50, days=60),
    )
    gaps = detect_coverage_gaps(state)
    assert [g.region for g in gaps] == ["a-region", "m-region", "z-region"]


# ---------------------------------------------------------------------------
# Empty / no-qualifying-regions
# ---------------------------------------------------------------------------


def test_empty_state_returns_empty_tuple() -> None:
    assert detect_coverage_gaps(SiblingState()) == ()


def test_all_regions_below_threshold_returns_empty() -> None:
    state = _state(
        _region("a", asset_count=5),
        _region("b", asset_count=8),
    )
    assert detect_coverage_gaps(state) == ()


# ---------------------------------------------------------------------------
# Threshold overrides
# ---------------------------------------------------------------------------


def test_negative_min_asset_count_rejected() -> None:
    with pytest.raises(ValueError, match="min_asset_count"):
        detect_coverage_gaps(SiblingState(), min_asset_count=0)


def test_custom_thresholds_change_qualification() -> None:
    """A region with 15 days gap doesn't qualify under default 30d
    but does under custom min_gap_days=10."""
    state = _state(_region("us-east-1", asset_count=20, days=15))
    assert detect_coverage_gaps(state, min_gap_days=10)
    assert not detect_coverage_gaps(state, min_gap_days=30)


# ---------------------------------------------------------------------------
# Output shape contracts
# ---------------------------------------------------------------------------


def test_output_is_tuple() -> None:
    """tuple — frozen, hashable, can be reused as a key for caching
    in the hypothesizer if needed."""
    state = _state(_region("us-east-1", asset_count=20, days=40))
    result = detect_coverage_gaps(state)
    assert isinstance(result, tuple)


def test_days_since_normalized_for_never_scanned() -> None:
    """RegionState's -1 sentinel is preserved as the gap signal but
    the CoverageGap output normalizes the field to >=0 (schema's
    ge=0 constraint). The 'never scanned' fact lives in the
    qualification check, not the field value."""
    state = _state(_region("ap-south-1", asset_count=12, days=-1))
    gaps = detect_coverage_gaps(state)
    assert gaps[0].days_since_last_finding == 0
