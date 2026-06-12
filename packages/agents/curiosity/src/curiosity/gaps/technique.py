"""Technique-gap detection (curiosity v0.2 Task 8, Q4 — NEW).

A **technique gap** is a MITRE ATT&CK technique that is *expected* for a tenant (surfaced by D.8
Threat Intel as relevant to their environment) but has **not been seen in a D.3/D.4 detection for
N days** — i.e. the fleet may not be testing for it. Pure + deterministic over caller-supplied
aggregates (the reader/driver derives ``expected_techniques`` from D.8 and ``last_seen_days`` from
D.3/D.4 detection history). Per WI-X1 technique-gap coverage is tracked separately from region/time.

The ``coverage_gap_id`` namespace is ``technique:<technique_id>``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

#: Default staleness floor — a technique unseen this many days counts as a gap.
DEFAULT_TECHNIQUE_GAP_DAYS = 30

#: Sentinel: the technique has never been seen in a detection.
NEVER_SEEN = -1

_SEVERITY_HIGH_FLOOR = 90
_SEVERITY_MEDIUM_FLOOR = 60


@dataclass(frozen=True, slots=True)
class TechniqueGap:
    technique_id: str
    days_since_last_seen: int  # NEVER_SEEN (-1) means never observed in a detection.
    severity_hint: str


def technique_coverage_gap_id(technique_id: str) -> str:
    """The ``coverage_gap_id`` a hypothesis cites for a technique gap."""
    return f"technique:{technique_id}"


def _severity_hint(days: int) -> str:
    # Never-seen is the most urgent; otherwise the staler, the higher.
    if days == NEVER_SEEN or days >= _SEVERITY_HIGH_FLOOR:
        return "high"
    if days >= _SEVERITY_MEDIUM_FLOOR:
        return "medium"
    return "low"


def detect_technique_gaps(
    *,
    expected_techniques: Iterable[str],
    last_seen_days: Mapping[str, int],
    min_gap_days: int = DEFAULT_TECHNIQUE_GAP_DAYS,
) -> tuple[TechniqueGap, ...]:
    """Return expected techniques unseen for >= ``min_gap_days`` (or never), staleness-first.

    A technique absent from ``last_seen_days`` is treated as never seen (the strongest signal).
    Ordered by staleness descending (never-seen first), then technique_id for determinism.
    """
    if min_gap_days < 1:
        raise ValueError(f"min_gap_days must be >= 1; got {min_gap_days}")

    gaps: list[TechniqueGap] = []
    for technique_id in dict.fromkeys(expected_techniques):  # dedup, preserve order
        if not technique_id:
            continue
        days = last_seen_days.get(technique_id)
        if days is None:
            gaps.append(TechniqueGap(technique_id, NEVER_SEEN, _severity_hint(NEVER_SEEN)))
        elif days >= min_gap_days:
            gaps.append(TechniqueGap(technique_id, days, _severity_hint(days)))

    # Staleness-first: never-seen (sentinel) ranks above any finite day-count.
    def _rank(gap: TechniqueGap) -> tuple[int, str]:
        effective = 10**9 if gap.days_since_last_seen == NEVER_SEEN else gap.days_since_last_seen
        return (-effective, gap.technique_id)

    gaps.sort(key=_rank)
    return tuple(gaps)
