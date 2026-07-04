"""Tests — ``nexus scan`` CLI command (Task 2, operating-path wiring).

Smoke test: the scan command exists, renders the feeder coverage line, and
exits 0.  scan_run + build_session_factory are both monkeypatched so the test
needs no DB or live agents.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner
from meta_harness import cli as cli_mod
from nexus_runtime.scan_pipeline import FeederOutcome, ScanRunResult


def _make_fake_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch build_session_factory + scan_run with no-op stubs."""

    async def _fake_build_session_factory(dsn: str) -> object:
        return object()

    async def _fake_scan_run(**kwargs: object) -> ScanRunResult:
        return ScanRunResult(
            confirmed=[],
            candidates=[],
            feeders=[FeederOutcome("data-security", True)],
        )

    import charter.memory.provisioning as prov_mod
    import nexus_runtime.scan_pipeline as sp_mod

    monkeypatch.setattr(prov_mod, "build_session_factory", _fake_build_session_factory)
    monkeypatch.setattr(sp_mod, "scan_run", _fake_scan_run)


def test_scan_command_renders_result(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    """scan command renders feeder lines + exits 0 with both stubs in place."""
    _make_fake_stubs(monkeypatch)

    inv_path = Path(tempfile.mkdtemp()) / "inv.json"
    inv_path.write_text("[]")

    result = CliRunner().invoke(
        cli_mod.main,
        [
            "scan",
            "--customer-id",
            "t1",
            "--dsn",
            "postgresql+asyncpg://fake/db",
            "--ds-inventory-feed",
            str(inv_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "data-security" in result.output  # feeder coverage line rendered


def test_scan_command_json_output(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    """--json flag emits valid JSON with feeders/confirmed/candidates keys."""
    _make_fake_stubs(monkeypatch)

    inv_path = Path(tempfile.mkdtemp()) / "inv.json"
    inv_path.write_text("[]")

    result = CliRunner().invoke(
        cli_mod.main,
        [
            "scan",
            "--customer-id",
            "t1",
            "--dsn",
            "postgresql+asyncpg://fake/db",
            "--ds-inventory-feed",
            str(inv_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert "feeders" in data, f"missing 'feeders' key; got: {list(data)}"
    assert "confirmed" in data, f"missing 'confirmed' key; got: {list(data)}"
    assert "candidates" in data, f"missing 'candidates' key; got: {list(data)}"
    # Verify feeder entry structure.
    assert len(data["feeders"]) == 1
    feeder = data["feeders"][0]
    assert feeder["agent"] == "data-security"
    assert feeder["ok"] is True
    assert feeder["error"] is None
