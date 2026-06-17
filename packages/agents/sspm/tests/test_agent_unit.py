"""Unit tests for the SSPM agent driver (D.10 PR1 skeleton).

PR1 has no connectors yet, so a run produces an empty-but-valid artifact set. These pin
the skeleton's charter wiring + output contract; connector behaviour lands in PR2-4.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter import ToolRegistry
from charter.contract import BudgetSpec, ExecutionContract
from sspm.agent import build_registry, run


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="sspm",
        customer_id="cust_test",
        task="SaaS posture scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=100, mb_written=10
        ),
        permitted_tools=["github_org_scan", "m365_scan", "slack_scan"],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def test_build_registry_returns_a_registry() -> None:
    # Empty in PR1; connectors register their tools here in PR2-4.
    assert isinstance(build_registry(), ToolRegistry)


@pytest.mark.asyncio
async def test_empty_run_writes_valid_artifacts(tmp_path: Path) -> None:
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert report.agent == "sspm"

    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert doc["agent"] == "sspm"
    assert doc["customer_id"] == "cust_test"
    assert doc["findings"] == []

    summary = (tmp_path / "ws" / "summary.md").read_text()
    assert "SaaS Security Posture" in summary


@pytest.mark.asyncio
async def test_semantic_store_default_is_inert(tmp_path: Path) -> None:
    # semantic_store defaults to None (PR5 kg_writer consumes it); a run is byte-identical.
    report = await run(_contract(tmp_path), semantic_store=None)
    assert report.total == 0
