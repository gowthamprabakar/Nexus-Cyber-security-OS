"""ScanScheduler — cadence-based due-tenant selection for the scan loop (Task 12).

Task 13: run_due_scans integration test is also here.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from charter.memory.models import Base
from nexus_runtime.continuous import ContinuousDriver
from nexus_runtime.scan_pipeline import ScanRunResult, ScanSources
from nexus_runtime.scan_scheduler import ScanScheduler, run_due_scans
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_T0 = datetime(2026, 6, 13, tzinfo=UTC)
_1H = timedelta(hours=1)
_TENANT = "t1"


def test_never_run_tenant_is_due_immediately() -> None:
    sched = ScanScheduler(tenants=["acme"], cadence=_1H)
    assert "acme" in sched.due(_T0)


def test_after_mark_ran_tenant_is_not_due_before_cadence() -> None:
    sched = ScanScheduler(tenants=["acme"], cadence=_1H)
    sched.mark_ran("acme", at=_T0)
    assert sched.due(_T0 + timedelta(minutes=30)) == []


def test_tenant_is_due_again_after_cadence() -> None:
    sched = ScanScheduler(tenants=["acme"], cadence=_1H)
    sched.mark_ran("acme", at=_T0)
    assert "acme" in sched.due(_T0 + timedelta(minutes=61))


def test_boundary_exactly_at_cadence_is_due() -> None:
    """last_ran + cadence <= now — equality makes it due."""
    sched = ScanScheduler(tenants=["acme"], cadence=_1H)
    sched.mark_ran("acme", at=_T0)
    assert "acme" in sched.due(_T0 + _1H)


def test_multiple_tenants_independent() -> None:
    sched = ScanScheduler(tenants=["acme", "beta"], cadence=_1H)
    sched.mark_ran("acme", at=_T0)
    # acme not yet due; beta never ran → still due
    result = sched.due(_T0 + timedelta(minutes=30))
    assert "acme" not in result
    assert "beta" in result


def test_due_order_matches_tenants_order() -> None:
    sched = ScanScheduler(tenants=["a", "b", "c"], cadence=_1H)
    assert sched.due(_T0) == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# Task 13: run_due_scans integration
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.mark.asyncio
async def test_run_due_scans_invokes_scan_run_for_due_tenant(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """run_due_scans drives scan_run for every tenant the registered ScanScheduler marks due.

    Assertions:
      (a) scan_run was invoked for t1 — spy via sources_for call log.
      (b) after the tick, t1 is no longer due at the same 'now' (tick marked it ran).
    """
    driver = ContinuousDriver()
    sched = ScanScheduler(tenants=[_TENANT], cadence=_1H)
    driver.register("scan", sched)

    # Spy: record which tenants sources_for was called for.
    called_for: list[str] = []

    def sources_for(tenant_id: str) -> ScanSources:
        called_for.append(tenant_id)
        # Empty sources — no feeder fires, but scan_run still returns a ScanRunResult.
        return ScanSources()

    results = await run_due_scans(
        driver=driver,
        now=_T0,
        session_factory=session_factory,
        sources_for=sources_for,
        workspace_root=tmp_path / "ws",
    )

    # (a) scan_run was invoked for t1
    assert called_for == [_TENANT], (
        f"sources_for was called for {called_for!r}, expected ['{_TENANT}']"
    )
    assert len(results) == 1
    assert isinstance(results[0], ScanRunResult)

    # (b) t1 is no longer due at the same now (tick marked it ran)
    assert sched.due(_T0) == [], (
        f"t1 should no longer be due at T0 after tick; got {sched.due(_T0)!r}"
    )
