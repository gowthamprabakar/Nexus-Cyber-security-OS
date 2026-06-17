"""Unit tests for the AI-SPM agent driver (D.11 PR1 skeleton)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aispm.agent import build_registry, run
from charter import ToolRegistry
from charter.contract import BudgetSpec, ExecutionContract


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="aispm",
        customer_id="cust_test",
        task="AI posture scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=100, mb_written=10
        ),
        permitted_tools=["discover_bedrock", "discover_sagemaker"],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def test_build_registry_returns_a_registry() -> None:
    # Empty in PR1; discovery + Garak tools register here in PR2-4.
    assert isinstance(build_registry(), ToolRegistry)


@pytest.mark.asyncio
async def test_empty_run_writes_valid_artifacts(tmp_path: Path) -> None:
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert report.agent == "aispm"

    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert doc["agent"] == "aispm"
    assert doc["customer_id"] == "cust_test"
    assert doc["findings"] == []

    assert "AI Security Posture" in (tmp_path / "ws" / "summary.md").read_text()


@pytest.mark.asyncio
async def test_semantic_store_default_is_inert(tmp_path: Path) -> None:
    report = await run(_contract(tmp_path), semantic_store=None)
    assert report.total == 0
