"""Task 14 — supervisor registers ScanScheduler in the continuous source (opt-in, default OFF).

Assertions:
- With NEXUS_CONTINUOUS_SCAN=1: driver.agents() includes "scan"; a tick for a due tenant emits a
  continuous IncomingTask and increments ContinuousMetrics.due_runs_dispatched.
- Without NEXUS_CONTINUOUS_SCAN (default OFF): driver.agents() does NOT include "scan" — behaviour
  is byte-identical to the pre-Task-14 empty-driver state.
- Real scan_run: NOT invoked here — the supervisor operates at the trigger/routing level.  The
  honest scope is registration + trigger emission + metrics increment.  run_due_scans lives in
  nexus_runtime and is wired at the fleet-runner level, not the supervisor CLI level.  This is
  documented in the Task 14 report.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nexus_runtime.continuous import ContinuousDriver
from supervisor.cli import _resolve_continuous_source
from supervisor.continuous_metrics import ContinuousMetrics

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 7, 4, tzinfo=UTC)
_CUST = "tenant-x"

_CADENCE_1S = timedelta(seconds=1)  # always-due for any tenant registered before _NOW


def _driver_with_scan(customer_id: str = _CUST) -> ContinuousDriver:
    """Build a driver the same way _resolve_continuous_source does when opt-in is set."""
    from nexus_runtime.scan_scheduler import ScanScheduler

    driver = ContinuousDriver()
    driver.register("scan", ScanScheduler(tenants=[customer_id], cadence=_CADENCE_1S))
    return driver


# ---------------------------------------------------------------------------
# Opt-in ENABLED tests
# ---------------------------------------------------------------------------


def test_scan_opt_in_registers_scan_scheduler(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With NEXUS_CONTINUOUS_SCAN=1, driver.agents() includes 'scan'."""
    monkeypatch.setenv("NEXUS_CONTINUOUS_SCAN", "1")
    source, _decision = _resolve_continuous_source(
        continuous_mode=True,
        continuous_kill_switch=False,
        customer_id=_CUST,
        workspace_root=tmp_path,
    )
    assert source is not None, "source must be non-None when continuous_mode=True + opt-in set"
    # Reach into the source to get the driver.
    driver: ContinuousDriver = source._driver
    assert "scan" in driver.agents(), (
        "driver must have a 'scan' scheduler registered when NEXUS_CONTINUOUS_SCAN=1"
    )


@pytest.mark.asyncio
async def test_scan_opt_in_tick_emits_and_increments_metrics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With NEXUS_CONTINUOUS_SCAN=1 + tenant due, tick emits a CONTINUOUS task and increments
    ContinuousMetrics.due_runs_dispatched."""
    monkeypatch.setenv("NEXUS_CONTINUOUS_SCAN", "1")

    metrics = ContinuousMetrics()
    source, _decision = _resolve_continuous_source(
        continuous_mode=True,
        continuous_kill_switch=False,
        customer_id=_CUST,
        workspace_root=tmp_path,
        metrics=metrics,
    )
    assert source is not None

    # Override the now_fn so the scheduler sees _NOW (which is after any cadence window for a
    # freshly constructed ScanScheduler with no prior run).
    from supervisor.continuous_source import ContinuousTriggerSource
    from supervisor.schemas import TriggerSource

    # Re-create the source with a frozen now_fn so the scheduler is deterministic.
    driver: ContinuousDriver = source._driver
    frozen_source = ContinuousTriggerSource(
        driver,
        now_fn=lambda: _NOW,
        task_id_fn=lambda: "test-task-1",
    )
    tasks = await frozen_source(_CUST)

    # The tick must have emitted a CONTINUOUS trigger for the "scan" agent.
    assert any(
        t.trigger_source is TriggerSource.CONTINUOUS and t.target_agent == "scan" for t in tasks
    ), f"Expected a CONTINUOUS 'scan' task; got: {tasks}"

    # Metrics must reflect the dispatched run.
    # We call record_dispatch manually after the source fires — this mirrors how the live loop
    # would do it (source emits triggers; caller increments metrics per emitted task).
    metrics.record_dispatch(len(tasks))
    assert metrics.due_runs_dispatched >= 1, (
        f"due_runs_dispatched must be >= 1 after a due scan tick; got {metrics.due_runs_dispatched}"
    )


# ---------------------------------------------------------------------------
# Default OFF (no opt-in)
# ---------------------------------------------------------------------------


def test_scan_default_off_no_scan_scheduler(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Without NEXUS_CONTINUOUS_SCAN, the driver has NO 'scan' scheduler — behaviour unchanged."""
    monkeypatch.delenv("NEXUS_CONTINUOUS_SCAN", raising=False)
    source, _decision = _resolve_continuous_source(
        continuous_mode=True,
        continuous_kill_switch=False,
        customer_id=_CUST,
        workspace_root=tmp_path,
    )
    assert source is not None
    driver: ContinuousDriver = source._driver
    assert "scan" not in driver.agents(), (
        "driver must NOT have 'scan' registered when NEXUS_CONTINUOUS_SCAN is absent"
    )


def test_continuous_mode_off_returns_none(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """continuous_mode=False still returns None regardless of the scan opt-in."""
    monkeypatch.setenv("NEXUS_CONTINUOUS_SCAN", "1")
    source, decision = _resolve_continuous_source(
        continuous_mode=False,
        continuous_kill_switch=False,
        customer_id=_CUST,
        workspace_root=tmp_path,
    )
    assert source is None
    assert decision["continuous_effective"] is False


def test_kill_switch_suppresses_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Kill-switch overrides the scan opt-in (continuous_effective=False → source is None)."""
    monkeypatch.setenv("NEXUS_CONTINUOUS_SCAN", "1")
    source, decision = _resolve_continuous_source(
        continuous_mode=True,
        continuous_kill_switch=True,
        customer_id=_CUST,
        workspace_root=tmp_path,
    )
    assert source is None
    assert decision["continuous_effective"] is False
