"""ScanScheduler — cadence-based tenant scheduling for the continuous scan loop (Task 12).

Implements ``SchedulerProtocol`` from ``nexus_runtime.continuous`` so the ``ContinuousDriver``
can register it directly:

    driver.register("data-security", ScanScheduler(tenants=[...], cadence=timedelta(hours=1)))

ponytail: in-memory last-ran map — swap for a persisted store (Redis / Postgres) when
multi-process scheduling matters (multiple driver workers sharing state).

Task 13 adds ``run_due_scans`` — the glue that turns a ``ContinuousDriver`` tick into actual
``scan_run`` calls per due tenant.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from nexus_runtime.continuous import ContinuousDriver
    from nexus_runtime.scan_pipeline import ScanRunResult, ScanSources


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


async def run_due_scans(
    *,
    driver: ContinuousDriver,
    now: datetime,
    session_factory: async_sessionmaker[AsyncSession],
    sources_for: Callable[[str], ScanSources],
    workspace_root: Path,
) -> list[ScanRunResult]:
    """Drive ``driver.tick`` so every due tenant gets a real ``scan_run`` call.

    Builds an async ``dispatch(agent_id, tenant_id)`` closure that calls
    ``scan_run`` for the given tenant (pulling its ``ScanSources`` from
    ``sources_for``), then delegates all scheduling decisions to
    ``driver.tick`` — which calls ``mark_ran`` on success so nothing here
    double-marks.

    Returns the list of ``ScanRunResult`` values (one per successfully
    dispatched run, in dispatch order).
    """
    from nexus_runtime.scan_pipeline import scan_run  # deferred to avoid circular

    results: list[ScanRunResult] = []

    async def dispatch(_agent_id: str, tenant_id: str) -> None:
        result = await scan_run(
            session_factory=session_factory,
            tenant=tenant_id,
            sources=sources_for(tenant_id),
            workspace_root=workspace_root,
        )
        results.append(result)

    await driver.tick(now, dispatch=dispatch)
    return results


__all__ = ["ScanScheduler", "run_due_scans"]
