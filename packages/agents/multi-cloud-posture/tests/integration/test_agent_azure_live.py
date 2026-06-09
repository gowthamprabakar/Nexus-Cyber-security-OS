"""D.5 v0.2 Task 15 — live-Azure integration tests (read-only).

Gated by the `azure_live_subscription` fixture (`NEXUS_LIVE_AZURE=1` + reachable);
**skips cleanly** otherwise, so CI never touches Azure. Read-only, single
subscription (Q6). Exercises the live seams D.5 v0.2 built — credential
resolution + subscription/region discovery — and the agent's OCSF 2003 output +
audit chain. Operator-run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter import verify_audit_log
from charter.contract import BudgetSpec, ExecutionContract
from multi_cloud_posture.agent import run
from multi_cloud_posture.credentials_azure import AzureCredentialResolver
from multi_cloud_posture.schemas import FindingsReport
from multi_cloud_posture.tools.azure_discovery import discover_locations

pytestmark = pytest.mark.integration


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="multi_cloud_posture",
        customer_id="cust_live_azure",
        task="Read-only live-Azure posture scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=300.0, cloud_api_calls=100_000, mb_written=50
        ),
        permitted_tools=[
            "read_azure_findings",
            "read_azure_activity",
            "read_gcp_findings",
            "read_gcp_iam_findings",
        ],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )


@pytest.mark.asyncio
async def test_subscription_discovered_live(azure_live_subscription: str) -> None:
    assert azure_live_subscription  # a real, non-empty subscription id


@pytest.mark.asyncio
async def test_locations_enumerated_live(azure_live_subscription: str) -> None:
    locations = await discover_locations(AzureCredentialResolver(), azure_live_subscription)
    assert locations
    assert all(isinstance(loc, str) and loc for loc in locations)


@pytest.mark.asyncio
async def test_credential_resolves_live(azure_live_subscription: str) -> None:
    assert AzureCredentialResolver().resolve_credential() is not None


@pytest.mark.asyncio
async def test_agent_run_writes_valid_ocsf_2003(
    tmp_path: Path, azure_live_subscription: str
) -> None:
    contract = _contract(tmp_path)
    await run(contract=contract, azure_subscription_id=azure_live_subscription)
    raw = (Path(contract.workspace) / "findings.json").read_text(encoding="utf-8")
    report = FindingsReport.model_validate_json(raw)
    for f in report.findings:
        assert f["class_uid"] == 2003


@pytest.mark.asyncio
async def test_agent_run_audit_chain_valid(tmp_path: Path, azure_live_subscription: str) -> None:
    contract = _contract(tmp_path)
    await run(contract=contract, azure_subscription_id=azure_live_subscription)
    result = verify_audit_log(Path(contract.workspace) / "audit.jsonl")
    assert result.valid is True
    assert result.broken_at is None


@pytest.mark.asyncio
async def test_agent_run_writes_report_md(tmp_path: Path, azure_live_subscription: str) -> None:
    contract = _contract(tmp_path)
    await run(contract=contract, azure_subscription_id=azure_live_subscription)
    report_md = (Path(contract.workspace) / "report.md").read_text(encoding="utf-8")
    assert report_md.startswith("# Multi-Cloud Posture Scan")
