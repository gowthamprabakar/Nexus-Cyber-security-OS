"""Multi-agent dispatch orchestration (supervisor v0.2 Task 4, Q1).

Adds cross-agent **dependency awareness** + **result aggregation** on top of the Task-3 live
dispatch. Some agents consume others' findings — compliance (D.6) rolls up the posture agents'
results — so targets are ordered into **waves**: each wave dispatches in parallel, and a wave
runs only after the waves carrying its prerequisites. Per-delegation timeout is already
enforced by ``dispatch_parallel`` (the H3 budget invariant via ``budget_wall_clock_sec``);
this module sequences the waves and summarizes the outcomes. Pure + declarative.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from supervisor.schemas import DelegationOutcome, DelegationStatus

#: Cross-agent dispatch dependencies — a target's prerequisites (which must dispatch first).
#: compliance (D.6) consumes the cloud / multi-cloud / k8s posture findings.
DISPATCH_DEPENDENCIES: dict[str, frozenset[str]] = {
    "compliance": frozenset({"cloud_posture", "multi_cloud_posture", "k8s_posture"}),
}


def order_by_dependencies(targets: Sequence[str]) -> list[tuple[str, ...]]:
    """Group ``targets`` into dependency-ordered waves. Only prerequisites that are themselves
    in ``targets`` constrain ordering (an absent dependency does not block). Deterministic;
    input order is preserved within a wave."""
    remaining = list(dict.fromkeys(targets))  # dedup, preserve first-seen order
    in_scope = set(remaining)
    placed: set[str] = set()
    waves: list[tuple[str, ...]] = []
    while remaining:
        wave = [
            t for t in remaining if (DISPATCH_DEPENDENCIES.get(t, frozenset()) & in_scope) <= placed
        ]
        if not wave:  # defensive: unsatisfiable/cycle -> emit the rest as one wave
            wave = list(remaining)
        waves.append(tuple(wave))
        placed |= set(wave)
        remaining = [t for t in remaining if t not in placed]
    return waves


@dataclass(frozen=True, slots=True)
class OrchestrationSummary:
    total: int
    ok: int
    error: int
    timeout: int
    by_agent: dict[str, str]  # agent_id -> status value

    @property
    def all_ok(self) -> bool:
        return self.total > 0 and self.ok == self.total


def aggregate_outcomes(outcomes: Sequence[DelegationOutcome]) -> OrchestrationSummary:
    """Summarize delegation outcomes across (possibly several) waves."""
    ok = sum(1 for o in outcomes if o.status is DelegationStatus.OK)
    error = sum(1 for o in outcomes if o.status is DelegationStatus.ERROR)
    timeout = sum(1 for o in outcomes if o.status is DelegationStatus.TIMEOUT_PARTIAL)
    by_agent = {o.target_agent: o.status.value for o in outcomes}
    return OrchestrationSummary(
        total=len(outcomes), ok=ok, error=error, timeout=timeout, by_agent=by_agent
    )
