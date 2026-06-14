"""Continuous-mode metrics (Track D D-2).

An **activation prerequisite** (audit §11): v0.3 BUILDS the metrics surface;
v0.4 ACTIVATES it (a live loop increments the counters). In v0.3 this is an
inert, in-process counter — constructed, queryable via :meth:`snapshot`, but
with the D-1 empty ``ContinuousDriver`` no ticks fire, so every counter stays
0. Nothing here starts a loop (pause trigger #25 stays clear).

Deliberately a **plain stdlib dataclass** — no Prometheus, no new dependency.
``nexus_runtime`` is ``dependencies = []`` (the canary); this metrics type is
supervisor-local and adds no dep there or in charter/shared (substrate seal
empty).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ContinuousMetrics:
    """In-process counters for continuous-mode observability.

    Counters: ``ticks`` (loop ticks observed), ``due_runs_dispatched`` (trigger
    tasks emitted), ``dispatch_errors`` (failed dispatches). ``per_tenant_cadence``
    labels the configured cadence per tenant (set from the resolved cadence
    config, not from a live loop). All increments are no-ops until a v0.4 loop
    calls them, so a v0.3 run leaves every counter at 0.
    """

    ticks: int = 0
    due_runs_dispatched: int = 0
    dispatch_errors: int = 0
    per_tenant_cadence: dict[str, str] = field(default_factory=dict)

    def record_tick(self) -> None:
        self.ticks += 1

    def record_dispatch(self, count: int = 1) -> None:
        if count < 0:
            raise ValueError(f"dispatch count must be >= 0, got {count}")
        self.due_runs_dispatched += count

    def record_error(self, count: int = 1) -> None:
        if count < 0:
            raise ValueError(f"error count must be >= 0, got {count}")
        self.dispatch_errors += count

    def set_cadence(self, tenant_id: str, cadence: str) -> None:
        """Label a tenant's configured cadence (inert — config, not a live tick)."""
        self.per_tenant_cadence[tenant_id] = cadence

    def error_rate(self) -> float:
        """Failed dispatches / total dispatch attempts; 0.0 when none attempted."""
        attempts = self.due_runs_dispatched + self.dispatch_errors
        return self.dispatch_errors / attempts if attempts else 0.0

    def snapshot(self) -> dict[str, Any]:
        """A JSON-serializable point-in-time view (for the status-page stub)."""
        return {
            "ticks": self.ticks,
            "due_runs_dispatched": self.due_runs_dispatched,
            "dispatch_errors": self.dispatch_errors,
            "error_rate": self.error_rate(),
            "per_tenant_cadence": dict(self.per_tenant_cadence),
        }
