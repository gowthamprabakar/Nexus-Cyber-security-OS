"""ScanScheduler — cadence-based tenant scheduling for the continuous scan loop (Task 12).

Implements ``SchedulerProtocol`` from ``nexus_runtime.continuous`` so the ``ContinuousDriver``
can register it directly:

    driver.register("data-security", ScanScheduler(tenants=[...], cadence=timedelta(hours=1)))

ponytail: in-memory last-ran map — swap for a persisted store (Redis / Postgres) when
multi-process scheduling matters (multiple driver workers sharing state).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta


class ScanScheduler:
    """Cadence-based scheduler: returns tenants whose ``last_ran + cadence <= now``.

    Tenants that have never run are considered immediately due.
    Satisfies ``SchedulerProtocol`` structurally (mypy checks at ``driver.register`` call site).
    """

    def __init__(self, *, tenants: Sequence[str], cadence: timedelta) -> None:
        self._tenants: tuple[str, ...] = tuple(tenants)
        self._cadence: timedelta = cadence
        # in-memory last-ran map; absent key → never ran → always due
        self._last_ran: dict[str, datetime] = {}

    def due(self, now: datetime) -> list[str]:
        """Return tenant ids whose ``last_ran + cadence <= now`` (preserving tenants order).

        Tenants never marked ran are always included.
        """
        result: list[str] = []
        for tenant in self._tenants:
            last = self._last_ran.get(tenant)
            if last is None or last + self._cadence <= now:
                result.append(tenant)
        return result

    def mark_ran(self, tenant_id: str, *, at: datetime) -> None:
        """Record that ``tenant_id`` ran at ``at``."""
        self._last_ran[tenant_id] = at
