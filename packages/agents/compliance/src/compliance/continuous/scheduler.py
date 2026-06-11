"""Background scan scheduler (compliance v0.2 Task 12).

Per **Q4 / WI-C4** this is continuous-monitoring **INFRASTRUCTURE only** — it decides WHEN
each framework is due for a re-scan, deterministically (caller-provided ``now``). It does
**not** run scans and is **not** wired into ``agent.run()``; driving the production loop is
the **Phase C** consolidated retrofit (pause-trigger #11 guards against wiring it here).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(slots=True)
class ScanSchedule:
    framework: str
    interval_seconds: int
    last_run_at: datetime | None = None


class ScanScheduler:
    """Tracks per-framework scan intervals + computes which frameworks are due."""

    def __init__(self) -> None:
        self._schedules: dict[str, ScanSchedule] = {}

    def register(self, framework: str, *, interval_seconds: int) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._schedules[framework] = ScanSchedule(framework, interval_seconds)

    def frameworks(self) -> tuple[str, ...]:
        return tuple(self._schedules)

    def mark_ran(self, framework: str, *, at: datetime) -> None:
        sched = self._schedules.get(framework)
        if sched is None:
            raise KeyError(f"framework {framework!r} is not registered")
        sched.last_run_at = at

    def next_due_at(self, framework: str) -> datetime | None:
        """When the framework is next due (``None`` if never run — due immediately)."""
        sched = self._schedules[framework]
        if sched.last_run_at is None:
            return None
        return sched.last_run_at + timedelta(seconds=sched.interval_seconds)

    def due(self, now: datetime) -> list[str]:
        """The frameworks due for a scan at ``now`` — never-run ones are always due."""
        out: list[str] = []
        for framework, sched in self._schedules.items():
            if sched.last_run_at is None or now >= sched.last_run_at + timedelta(
                seconds=sched.interval_seconds
            ):
                out.append(framework)
        return out
