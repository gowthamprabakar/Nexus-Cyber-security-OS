"""Stage 2 DETECT — deterministic region-gap detector.

Pure function over the Stage 1 ``SiblingState`` snapshot. Returns
the list of regions that look like coverage gaps — regions with
substantial asset inventory but no recent finding activity. The
LLM hypothesizer (Stage 3) consumes the returned ``CoverageGap``
tuple as its grounding context.

**v0.1: region-gap only.**

A region is a gap when **both** conditions hold:

1. ``asset_count >= _MIN_ASSET_COUNT`` (default 10) — enough
   assets that a coverage hole is operationally meaningful.
2. ``days_since_last_finding < 0`` (sentinel: "no findings ever
   observed") OR
   ``days_since_last_finding >= _MIN_GAP_DAYS`` (default 30) —
   long enough that "clean posture" is less likely than "we
   forgot to scan here."

Regions that pass both checks become ``CoverageGap`` entries
ordered by ``asset_count`` descending — the biggest blast-radius
gaps appear first so the hypothesizer's max-5-cap surfaces them
preferentially.

**Severity hint** is a lightweight bucketing for the LLM prompt:

- ``asset_count >= 100`` -> ``"high"``
- ``asset_count >= 30``  -> ``"medium"``
- otherwise              -> ``"low"``

The hypothesizer uses ``severity_hint`` to tune the urgency of the
generated probe directive but is not bound by it; the deterministic
floor is the asset-count threshold above.

**Deferred to v0.2/v0.3.** Asset-type gap (zero findings in any
EC2 / RDS / S3 / Lambda class despite inventory). Time-window
gap (gradual finding-rate decay vs. baseline). Severity-distribution
gap (no critical findings but high noise rate). Classifier-label
gap (no PII findings despite known PII-rich workloads). Control-
coverage gap (CIS controls with no per-tenant findings). Cross-
customer baseline drift.
"""

from __future__ import annotations

from collections.abc import Iterable

from curiosity.schemas import CoverageGap
from curiosity.tools.sibling_state_reader import RegionState, SiblingState

_MIN_ASSET_COUNT = 10
_MIN_GAP_DAYS = 30

_SEVERITY_HIGH_FLOOR = 100
_SEVERITY_MEDIUM_FLOOR = 30


def detect_coverage_gaps(
    state: SiblingState,
    *,
    min_asset_count: int = _MIN_ASSET_COUNT,
    min_gap_days: int = _MIN_GAP_DAYS,
) -> tuple[CoverageGap, ...]:
    """Return regions that look like under-scanned coverage gaps.

    Ordered by ``asset_count`` descending so the biggest gaps
    surface first.

    Args:
        state: Stage 1 INGEST output.
        min_asset_count: Lower bound on a region's asset count for
            the gap to be operationally meaningful. Default 10.
            Tightening below 1 raises ``ValueError`` (no-asset gaps
            are noise, never signal).
        min_gap_days: Lower bound on ``days_since_last_finding``
            for the region to count as a gap. Default 30.
            Regions with ``-1`` ("no findings ever") always qualify
            regardless of this threshold. Negative values other
            than ``-1`` are coerced via the same "no findings ever"
            interpretation.

    Returns:
        Tuple of ``CoverageGap`` entries, biggest first.
    """
    if min_asset_count < 1:
        raise ValueError(
            f"min_asset_count must be >= 1; got {min_asset_count} "
            "(no-asset gaps are noise, never signal)"
        )

    candidates = list(_iter_gaps(state.regions, min_asset_count, min_gap_days))
    candidates.sort(key=lambda g: (-g.asset_count, g.region))
    return tuple(candidates)


def _iter_gaps(
    regions: Iterable[RegionState],
    min_asset_count: int,
    min_gap_days: int,
) -> Iterable[CoverageGap]:
    for r in regions:
        if r.asset_count < min_asset_count:
            continue
        if not _qualifies_as_gap(r, min_gap_days):
            continue
        yield CoverageGap(
            region=r.region,
            asset_count=r.asset_count,
            days_since_last_finding=_normalize_days(r.days_since_last_finding),
            severity_hint=_severity_hint(r.asset_count),
        )


def _qualifies_as_gap(region: RegionState, min_gap_days: int) -> bool:
    """A region qualifies when it has no findings ever OR the
    gap exceeds the threshold."""
    if region.days_since_last_finding < 0:
        return True
    return region.days_since_last_finding >= min_gap_days


def _normalize_days(days: int) -> int:
    """Clamp negative day-counts to ``0`` for the CoverageGap field
    (which has ``ge=0`` per the schema). The "no findings ever"
    signal is preserved by the gap-qualification check above; the
    schema doesn't need to carry the sentinel."""
    return max(days, 0)


def _severity_hint(asset_count: int) -> str:
    if asset_count >= _SEVERITY_HIGH_FLOOR:
        return "high"
    if asset_count >= _SEVERITY_MEDIUM_FLOOR:
        return "medium"
    return "low"


__all__ = ["detect_coverage_gaps"]
