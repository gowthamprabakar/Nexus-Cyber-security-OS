"""Time-gap detection (curiosity v0.2 Task 9, Q4 — NEW).

A **time gap** is an asset class whose **last scan was more than N hours ago** (or never) — the
posture/runtime agents (F.3/D.5/k8s-posture) cycle on a cadence, and a class that has fallen off
that cadence may be silently under-covered. Pure + deterministic over caller-supplied cycle
history (``last_scan_hours``). Per WI-X1 time-gap coverage is tracked separately from
region/technique. The ``coverage_gap_id`` namespace is ``time:<asset_class>``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

#: Default cadence floor — an asset class unscanned this many hours counts as a gap (1 day).
DEFAULT_TIME_GAP_HOURS = 24

#: Sentinel: the asset class has never been scanned.
NEVER_SCANNED = -1

_SEVERITY_HIGH_FLOOR = 168  # 7 days
_SEVERITY_MEDIUM_FLOOR = 72  # 3 days


@dataclass(frozen=True, slots=True)
class TimeGap:
    asset_class: str
    hours_since_last_scan: int  # NEVER_SCANNED (-1) means never scanned.
    severity_hint: str


def time_coverage_gap_id(asset_class: str) -> str:
    """The ``coverage_gap_id`` a hypothesis cites for a time gap."""
    return f"time:{asset_class}"


def _severity_hint(hours: int) -> str:
    if hours == NEVER_SCANNED or hours >= _SEVERITY_HIGH_FLOOR:
        return "high"
    if hours >= _SEVERITY_MEDIUM_FLOOR:
        return "medium"
    return "low"


def detect_time_gaps(
    *,
    asset_classes: Iterable[str],
    last_scan_hours: Mapping[str, int],
    min_gap_hours: int = DEFAULT_TIME_GAP_HOURS,
) -> tuple[TimeGap, ...]:
    """Return asset classes unscanned for >= ``min_gap_hours`` (or never), staleness-first.

    A class absent from ``last_scan_hours`` is treated as never scanned (the strongest signal).
    Ordered by staleness descending (never-scanned first), then asset_class for determinism.
    """
    if min_gap_hours < 1:
        raise ValueError(f"min_gap_hours must be >= 1; got {min_gap_hours}")

    gaps: list[TimeGap] = []
    for asset_class in dict.fromkeys(asset_classes):  # dedup, preserve order
        if not asset_class:
            continue
        hours = last_scan_hours.get(asset_class)
        if hours is None:
            gaps.append(TimeGap(asset_class, NEVER_SCANNED, _severity_hint(NEVER_SCANNED)))
        elif hours >= min_gap_hours:
            gaps.append(TimeGap(asset_class, hours, _severity_hint(hours)))

    def _rank(gap: TimeGap) -> tuple[int, str]:
        effective = (
            10**9 if gap.hours_since_last_scan == NEVER_SCANNED else gap.hours_since_last_scan
        )
        return (-effective, gap.asset_class)

    gaps.sort(key=_rank)
    return tuple(gaps)
