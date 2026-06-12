"""investigation v0.2 Task 2 — fleet evidence reader tests (Q2/WI-I16)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from investigation.tools.fleet_evidence_reader import (
    SOURCE_AGENTS,
    TenantScopeError,
    read_fleet_evidence,
)

_TENANT = "01HV0T0000000000000000TENA"


def _workspace(tmp_path: Path, agent: str, n: int) -> Path:
    ws = tmp_path / agent
    ws.mkdir()
    (ws / "findings.json").write_text(
        json.dumps(
            {
                "agent": agent,
                "run_id": "r1",
                "findings": [
                    {"class_uid": 2004, "finding_info": {"uid": f"{agent}-{i}"}} for i in range(n)
                ],
            }
        ),
        encoding="utf-8",
    )
    return ws


def test_thirteen_source_agents() -> None:
    assert len(SOURCE_AGENTS) == 13
    assert {"supervisor", "synthesis", "audit", "compliance"} <= set(SOURCE_AGENTS)


@pytest.mark.asyncio
async def test_reads_multiple_sources(tmp_path: Path) -> None:
    ws = {
        "compliance": _workspace(tmp_path, "compliance", 2),
        "audit": _workspace(tmp_path, "audit", 1),
    }
    evidence = await read_fleet_evidence(ws, tenant_id=_TENANT)
    assert evidence.total == 3 and evidence.tenant_id == _TENANT
    assert len(evidence.for_agent("compliance")) == 2


@pytest.mark.asyncio
async def test_empty_tenant_rejected(tmp_path: Path) -> None:
    with pytest.raises(TenantScopeError, match="tenant_id"):
        await read_fleet_evidence({}, tenant_id="")


@pytest.mark.asyncio
async def test_missing_source_empty(tmp_path: Path) -> None:
    evidence = await read_fleet_evidence({"compliance": None}, tenant_id=_TENANT)
    assert evidence.total == 0 and evidence.for_agent("compliance") == ()


@pytest.mark.asyncio
async def test_unknown_agent_ignored(tmp_path: Path) -> None:
    ws = {"ghost": _workspace(tmp_path, "ghost", 3)}
    evidence = await read_fleet_evidence(ws, tenant_id=_TENANT)
    assert evidence.total == 0


@pytest.mark.asyncio
async def test_agents_with_evidence(tmp_path: Path) -> None:
    ws = {"synthesis": _workspace(tmp_path, "synthesis", 1)}
    evidence = await read_fleet_evidence(ws, tenant_id=_TENANT)
    assert evidence.agents_with_evidence() == ("synthesis",)


@pytest.mark.asyncio
async def test_all_thirteen_keys_present(tmp_path: Path) -> None:
    evidence = await read_fleet_evidence({}, tenant_id=_TENANT)
    assert set(evidence.by_agent) == set(SOURCE_AGENTS)
