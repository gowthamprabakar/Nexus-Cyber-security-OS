"""Delta detection across scan cycles (compliance v0.2 Task 13).

Compares two scan snapshots to surface what **changed** — newly-failing vs resolved rules,
and at the control level which controls **regressed** (newly fail) vs were **remediated**
(fail -> pass). Pure + deterministic; part of the continuous-monitoring INFRASTRUCTURE
(Q4/WI-C4) — the scheduler (Task 12) decides when to re-scan, this diffs the results. NOT
wired into ``agent.run()`` (Phase C).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from compliance.rollup import FAIL, PASS


@dataclass(frozen=True, slots=True)
class FindingDelta:
    newly_failing: tuple[str, ...] = field(default_factory=tuple)
    resolved: tuple[str, ...] = field(default_factory=tuple)
    still_failing: tuple[str, ...] = field(default_factory=tuple)

    @property
    def has_changes(self) -> bool:
        return bool(self.newly_failing or self.resolved)


def compute_delta(previous_failing: set[str], current_failing: set[str]) -> FindingDelta:
    """Diff two failing-rule snapshots → newly-failing / resolved / still-failing."""
    return FindingDelta(
        newly_failing=tuple(sorted(current_failing - previous_failing)),
        resolved=tuple(sorted(previous_failing - current_failing)),
        still_failing=tuple(sorted(current_failing & previous_failing)),
    )


@dataclass(frozen=True, slots=True)
class ControlStatusDelta:
    regressed: tuple[str, ...] = field(default_factory=tuple)  # -> FAIL this cycle
    remediated: tuple[str, ...] = field(default_factory=tuple)  # FAIL -> PASS

    @property
    def has_changes(self) -> bool:
        return bool(self.regressed or self.remediated)


def compute_control_delta(
    previous: Mapping[str, str], current: Mapping[str, str]
) -> ControlStatusDelta:
    """Diff two ``control_id -> status`` maps → regressed / remediated controls."""
    regressed = sorted(
        cid for cid, status in current.items() if status == FAIL and previous.get(cid) != FAIL
    )
    remediated = sorted(
        cid for cid, status in current.items() if status == PASS and previous.get(cid) == FAIL
    )
    return ControlStatusDelta(regressed=tuple(regressed), remediated=tuple(remediated))
