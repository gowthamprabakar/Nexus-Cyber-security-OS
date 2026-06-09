"""D.5 v0.2 Task 15 — live-GCP integration tests (read-only).

Gated by the `gcp_live_project` fixture (`NEXUS_LIVE_GCP=1` + reachable); **skips
cleanly** otherwise, so CI never touches GCP. Read-only, single project (Q6).
Exercises the live seams D.5 v0.2 built — ADC resolution + project/region
discovery — and the agent's OCSF 2003 output + audit chain. Operator-run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter import verify_audit_log
from charter.contract import BudgetSpec, ExecutionContract
from multi_cloud_posture.agent import run
from multi_cloud_posture.credentials_gcp import GcpCredentialResolver
from multi_cloud_posture.schemas import FindingsReport
from multi_cloud_posture.tools.gcp_discovery import discover_regions

pytestmark = pytest.mark.integration


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="multi_cloud_posture",
        customer_id="cust_live_gcp",
        task="Read-only live-GCP posture scan",
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
async def test_project_discovered_live(gcp_live_project: str) -> None:
    assert gcp_live_project  # a real, non-empty project id


@pytest.mark.asyncio
async def test_regions_enumerated_live(gcp_live_project: str) -> None:
    regions = await discover_regions(GcpCredentialResolver(), gcp_live_project)
    assert regions
    assert all(isinstance(r, str) and r for r in regions)


@pytest.mark.asyncio
async def test_credential_resolves_live(gcp_live_project: str) -> None:
    credentials, _project = GcpCredentialResolver().resolve_credential()
    assert credentials is not None


@pytest.mark.asyncio
async def test_agent_run_writes_valid_ocsf_2003(tmp_path: Path, gcp_live_project: str) -> None:
    contract = _contract(tmp_path)
    await run(contract=contract, gcp_project_id=gcp_live_project)
    raw = (Path(contract.workspace) / "findings.json").read_text(encoding="utf-8")
    report = FindingsReport.model_validate_json(raw)
    for f in report.findings:
        assert f["class_uid"] == 2003


@pytest.mark.asyncio
async def test_agent_run_audit_chain_valid(tmp_path: Path, gcp_live_project: str) -> None:
    contract = _contract(tmp_path)
    await run(contract=contract, gcp_project_id=gcp_live_project)
    result = verify_audit_log(Path(contract.workspace) / "audit.jsonl")
    assert result.valid is True
    assert result.broken_at is None


@pytest.mark.asyncio
async def test_agent_run_writes_report_md(tmp_path: Path, gcp_live_project: str) -> None:
    contract = _contract(tmp_path)
    await run(contract=contract, gcp_project_id=gcp_live_project)
    report_md = (Path(contract.workspace) / "report.md").read_text(encoding="utf-8")
    assert report_md.startswith("# Multi-Cloud Posture Scan")
