"""curiosity v0.2 Task 7 — per-tenant region-gap thresholds (Q4)."""

from __future__ import annotations

import pytest
from curiosity.gaps.region import (
    DEFAULT_REGION_THRESHOLDS,
    RegionGapThresholds,
    detect_region_gaps,
    resolve_region_thresholds,
)
from curiosity.tools.coverage_gap_detector import detect_coverage_gaps
from curiosity.tools.sibling_state_reader import RegionState, SiblingState

_TENANT = "01HV0T0000000000000000TENA"


def _state() -> SiblingState:
    return SiblingState(
        regions=(
            # 20 assets, last finding 15 days ago: a gap only under a tighter (<=15d) threshold.
            RegionState(
                region="eu-west-1",
                asset_count=20,
                days_since_last_finding=15,
                last_finding_severity="low",
            ),
        ),
        total_assets=20,
    )


def test_default_matches_v0_1_detector() -> None:
    state = _state()
    assert detect_region_gaps(state) == detect_coverage_gaps(state)


def test_default_thresholds_no_gap() -> None:
    # 15 days < default 30 -> not a gap.
    assert detect_region_gaps(_state()) == ()


def test_tenant_override_tightens_and_surfaces_gap() -> None:
    tight = RegionGapThresholds(min_asset_count=10, min_gap_days=10)
    gaps = detect_region_gaps(_state(), tight)
    assert len(gaps) == 1
    assert gaps[0].region == "eu-west-1"


def test_resolve_returns_override() -> None:
    tight = RegionGapThresholds(min_asset_count=5, min_gap_days=7)
    resolved = resolve_region_thresholds(_TENANT, overrides={_TENANT: tight})
    assert resolved is tight


def test_resolve_default_for_unknown_tenant() -> None:
    assert (
        resolve_region_thresholds("other", overrides={_TENANT: RegionGapThresholds()})
        is DEFAULT_REGION_THRESHOLDS
    )
    assert resolve_region_thresholds(_TENANT) is DEFAULT_REGION_THRESHOLDS


def test_invalid_threshold_rejected() -> None:
    with pytest.raises(ValueError, match="min_asset_count"):
        detect_region_gaps(_state(), RegionGapThresholds(min_asset_count=0))
