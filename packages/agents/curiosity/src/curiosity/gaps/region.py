"""Region-gap detection — per-tenant tunable thresholds (curiosity v0.2 Task 7, Q4).

A thin, additive layer over the v0.1 ``detect_coverage_gaps`` deterministic detector: it adds a
per-tenant threshold config so an operator can tighten/loosen the asset-count + staleness floors
for a specific tenant without touching the global default (which stays byte-identical, so the
stub-LLM eval is unaffected). The region ``coverage_gap_id`` namespace is ``region:<region>``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from curiosity.schemas import CoverageGap
from curiosity.tools.coverage_gap_detector import detect_coverage_gaps
from curiosity.tools.sibling_state_reader import SiblingState


@dataclass(frozen=True, slots=True)
class RegionGapThresholds:
    """Per-tenant region-gap sensitivity. Defaults match the v0.1 deterministic floor."""

    min_asset_count: int = 10
    min_gap_days: int = 30


#: The fleet-wide default — identical to the v0.1 detector floor (eval byte-identical).
DEFAULT_REGION_THRESHOLDS = RegionGapThresholds()


def resolve_region_thresholds(
    tenant_id: str,
    *,
    overrides: Mapping[str, RegionGapThresholds] | None = None,
) -> RegionGapThresholds:
    """Resolve a tenant's region thresholds — a per-tenant override, else the global default."""
    if overrides is not None and tenant_id in overrides:
        return overrides[tenant_id]
    return DEFAULT_REGION_THRESHOLDS


def detect_region_gaps(
    state: SiblingState,
    thresholds: RegionGapThresholds = DEFAULT_REGION_THRESHOLDS,
) -> tuple[CoverageGap, ...]:
    """Detect region gaps under the given thresholds (delegates to the v0.1 detector)."""
    return detect_coverage_gaps(
        state,
        min_asset_count=thresholds.min_asset_count,
        min_gap_days=thresholds.min_gap_days,
    )
