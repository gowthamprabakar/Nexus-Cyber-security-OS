"""synthesis v0.2 Task 5 — fleet workspace reader tests (Q3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from synthesis.tools.fleet_workspace_reader import (
    SOURCE_AGENTS,
    read_fleet_workspaces,
)


def _workspace(tmp_path: Path, agent: str, finding_ids: list[str]) -> Path:
    ws = tmp_path / agent
    ws.mkdir()
    (ws / "findings.json").write_text(
        json.dumps({"findings": [{"finding_info": {"uid": fid}} for fid in finding_ids]}),
        encoding="utf-8",
    )
    return ws


def test_twelve_source_agents() -> None:
    assert len(SOURCE_AGENTS) == 12
    assert "supervisor" not in SOURCE_AGENTS  # Q3: supervisor is not a source
    assert {"investigation", "compliance", "cloud_posture", "audit"} <= set(SOURCE_AGENTS)


@pytest.mark.asyncio
async def test_reads_multiple_sources(tmp_path: Path) -> None:
    ws = {
        "compliance": _workspace(tmp_path, "compliance", ["C-1", "C-2"]),
        "audit": _workspace(tmp_path, "audit", ["A-1"]),
    }
    fleet = await read_fleet_workspaces(ws)
    assert fleet.total == 3
    assert len(fleet.for_agent("compliance")) == 2 and len(fleet.for_agent("audit")) == 1


@pytest.mark.asyncio
async def test_missing_source_is_empty(tmp_path: Path) -> None:
    fleet = await read_fleet_workspaces({"compliance": None})
    assert fleet.total == 0 and fleet.for_agent("compliance") == ()


@pytest.mark.asyncio
async def test_agents_with_findings(tmp_path: Path) -> None:
    ws = {"data_security": _workspace(tmp_path, "data_security", ["D-1"])}
    fleet = await read_fleet_workspaces(ws)
    assert fleet.agents_with_findings() == ("data_security",)


@pytest.mark.asyncio
async def test_unknown_agent_ignored(tmp_path: Path) -> None:
    ws = {"ghost": _workspace(tmp_path, "ghost", ["X-1"])}
    fleet = await read_fleet_workspaces(ws)
    assert fleet.total == 0  # ghost is not a SOURCE_AGENT


@pytest.mark.asyncio
async def test_all_twelve_keys_present(tmp_path: Path) -> None:
    fleet = await read_fleet_workspaces({})
    assert set(fleet.by_agent) == set(SOURCE_AGENTS)


@pytest.mark.asyncio
async def test_malformed_findings_skipped(tmp_path: Path) -> None:
    ws = tmp_path / "compliance"
    ws.mkdir()
    (ws / "findings.json").write_text("{not json", encoding="utf-8")
    fleet = await read_fleet_workspaces({"compliance": ws})
    assert fleet.for_agent("compliance") == ()
