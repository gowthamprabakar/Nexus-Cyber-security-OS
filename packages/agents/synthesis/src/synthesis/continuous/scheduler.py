"""Continuous synthesis scheduler (synthesis v0.2 Task 13, Q7).

Per **WI-Y2** this is continuous-monitoring **INFRASTRUCTURE only** — it decides WHEN each
tenant is due for a re-synthesis, deterministically (caller-provided ``now``), with independent
per-tenant intervals. It does **not** run synthesis and is **not** wired into ``agent.run()``;
driving the production loop is the **Phase C** consolidated retrofit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(slots=True)
class TenantSchedule:
    customer_id: str
    interval_seconds: int
    last_run_at: datetime | None = None


class SynthesisScheduler:
    """Tracks per-tenant re-synthesis intervals + computes which tenants are due."""

    def __init__(self) -> None:
        self._schedules: dict[str, TenantSchedule] = {}

    def register(self, customer_id: str, *, interval_seconds: int) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._schedules[customer_id] = TenantSchedule(customer_id, interval_seconds)

    def tenants(self) -> tuple[str, ...]:
        return tuple(self._schedules)

    def mark_ran(self, customer_id: str, *, at: datetime) -> None:
        schedule = self._schedules.get(customer_id)
        if schedule is None:
            raise KeyError(f"tenant {customer_id!r} is not registered")
        schedule.last_run_at = at

    def next_due_at(self, customer_id: str) -> datetime | None:
        schedule = self._schedules[customer_id]
        if schedule.last_run_at is None:
            return None
        return schedule.last_run_at + timedelta(seconds=schedule.interval_seconds)

    def due(self, now: datetime) -> list[str]:
        """The tenants due for re-synthesis at ``now`` — never-run ones are always due."""
        out: list[str] = []
        for customer_id, schedule in self._schedules.items():
            if schedule.last_run_at is None or now >= schedule.last_run_at + timedelta(
                seconds=schedule.interval_seconds
            ):
                out.append(customer_id)
        return out
