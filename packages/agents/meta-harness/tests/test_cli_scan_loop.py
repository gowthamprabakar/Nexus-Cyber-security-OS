"""Tests — ``meta-harness scan-loop`` CLI command (Task 14b, operating-path wiring).

Smoke test: the scan-loop command exists, runs ONE tick (--once), calls scan_run
for the correct tenant, and exits 0.  build_session_factory + scan_run are both
monkeypatched so the test needs no DB or live agents.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner
from meta_harness import cli as cli_mod
from nexus_runtime.scan_pipeline import FeederOutcome, ScanRunResult


def test_scan_loop_once_calls_scan_run_for_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """--once: scan_run invoked for t1, exits 0, does not hang."""
    called_tenants: list[str] = []

    async def _fake_build_session_factory(dsn: str) -> object:
        return object()

    async def _fake_scan_run(**kwargs: object) -> ScanRunResult:
        called_tenants.append(str(kwargs.get("tenant", "")))
        return ScanRunResult(
            confirmed=[],
            candidates=[],
            feeders=[FeederOutcome("data-security", True)],
        )

    import charter.memory.provisioning as prov_mod
    import nexus_runtime.scan_pipeline as sp_mod

    monkeypatch.setattr(prov_mod, "build_session_factory", _fake_build_session_factory)
    monkeypatch.setattr(sp_mod, "scan_run", _fake_scan_run)

    result = CliRunner().invoke(
        cli_mod.main,
        [
            "scan-loop",
            "--customer-id",
            "t1",
            "--dsn",
            "sqlite+aiosqlite:///:memory:",
            "--once",
        ],
    )

    assert result.exit_code == 0, result.output
    # (a) scan_run was invoked for t1
    assert "t1" in called_tenants, f"scan_run not called for t1; called_tenants={called_tenants}"
    # (b) --once caused the loop to exit (test returns; not hanging)
    # — satisfied by the test completing at all.
