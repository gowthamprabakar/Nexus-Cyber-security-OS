"""Continuous curiosity scheduler (curiosity v0.2 Task 18, Q6/WI-X2).

Per **WI-X2** this is continuous-monitoring **INFRASTRUCTURE only**: it decides WHEN each tenant
is due for a re-scan, deterministically (caller-provided ``now``), with independent per-tenant
intervals. It does **not** run a scan and is **not** wired into ``agent.run()`` — driving the
production loop is the **Phase C** consolidated retrofit (the discipline every v0.2 cycle has
held). Tenant-scoped throughout (WI-X13). Pure + deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(slots=True)
class TenantSchedule:
    tenant_id: str
    interval_seconds: int
    last_run_at: datetime | None = None


class CuriosityScheduler:
    """Tracks per-tenant re-scan intervals + computes which tenants are due."""

    def __init__(self) -> None:
        self._schedules: dict[str, TenantSchedule] = {}

    def register(self, tenant_id: str, *, interval_seconds: int) -> None:
        if not tenant_id:
            raise ValueError("tenant_id must be non-empty (tenant-scoped, WI-X13)")
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._schedules[tenant_id] = TenantSchedule(tenant_id, interval_seconds)

    def tenants(self) -> tuple[str, ...]:
        return tuple(self._schedules)

    def mark_ran(self, tenant_id: str, *, at: datetime) -> None:
        schedule = self._schedules.get(tenant_id)
        if schedule is None:
            raise KeyError(f"tenant {tenant_id!r} is not registered")
        schedule.last_run_at = at

    def next_due_at(self, tenant_id: str) -> datetime | None:
        schedule = self._schedules[tenant_id]
        if schedule.last_run_at is None:
            return None
        return schedule.last_run_at + timedelta(seconds=schedule.interval_seconds)

    def due(self, now: datetime) -> list[str]:
        """The tenants due for a re-scan at ``now`` — never-run ones are always due."""
        out: list[str] = []
        for tenant_id, schedule in self._schedules.items():
            if schedule.last_run_at is None or now >= schedule.last_run_at + timedelta(
                seconds=schedule.interval_seconds
            ):
                out.append(tenant_id)
        return out
