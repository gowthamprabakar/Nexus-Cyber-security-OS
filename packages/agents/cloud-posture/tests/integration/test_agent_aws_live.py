"""F.3 v0.2 Task 7 — live-AWS integration tests (read-only).

These run the Cloud Posture agent end-to-end against a **real AWS account** via
live boto3 (IAM / S3) + Prowler. They are **gated** by the `aws_live_account`
fixture (`NEXUS_LIVE_AWS=1` + STS reachability) and **skip cleanly** otherwise,
so a normal `pytest` / CI run never touches AWS. Operator-run, like the v0.1
smoke; the `charter-f5-live.yml` lane (PR #252) can also run them.

Read-only only: no writes to AWS. Current-account only (Q4). Assertions are
robust to a clean account (0 findings) — they validate the OCSF wire contract,
the audit chain, and the Task-5 degraded-region behavior, not specific findings.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter import verify_audit_log
from charter.contract import BudgetSpec, ExecutionContract
from cloud_posture.agent import run
from cloud_posture.schemas import FindingsReport

pytestmark = pytest.mark.integration


def _live_contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_live_aws",
        task="Read-only live-AWS posture scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=300.0,
            cloud_api_calls=100_000,  # live Prowler is ~200 cloud_calls/region
            mb_written=50,
        ),
        permitted_tools=[
            "prowler_scan",
            "aws_s3_list_buckets",
            "aws_s3_describe",
            "aws_iam_list_users_without_mfa",
            "aws_iam_list_admin_policies",
        ],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )


def _findings_doc(contract: ExecutionContract) -> dict:
    return json.loads((Path(contract.workspace) / "findings.json").read_text(encoding="utf-8"))


@pytest.mark.asyncio
async def test_live_findings_json_is_valid_ocsf_2003(tmp_path: Path, aws_live_account: str) -> None:
    contract = _live_contract(tmp_path)
    await run(
        contract=contract,
        semantic_store=None,
        aws_account_id=aws_live_account,
        aws_region="us-east-1",
    )
    doc = _findings_doc(contract)
    # validates against the shared wire model (no schema drift)
    FindingsReport.model_validate(doc)
    for f in doc["findings"]:
        assert f["class_uid"] == 2003
        assert f["category_uid"] == 2
        assert f["metadata"]["version"] == "1.3.0"
        assert "uid" in f["finding_info"]
        assert isinstance(f["severity_id"], int)


@pytest.mark.asyncio
async def test_live_audit_chain_valid_end_to_end(tmp_path: Path, aws_live_account: str) -> None:
    contract = _live_contract(tmp_path)
    await run(
        contract=contract,
        semantic_store=None,
        aws_account_id=aws_live_account,
        aws_region="us-east-1",
    )
    result = verify_audit_log(Path(contract.workspace) / "audit.jsonl")
    assert result.valid is True
    assert result.entries_checked >= 1
    assert result.broken_at is None


@pytest.mark.asyncio
async def test_live_summary_md_written_with_header(tmp_path: Path, aws_live_account: str) -> None:
    contract = _live_contract(tmp_path)
    await run(
        contract=contract,
        semantic_store=None,
        aws_account_id=aws_live_account,
        aws_region="us-east-1",
    )
    summary = (Path(contract.workspace) / "summary.md").read_text(encoding="utf-8")
    assert summary.startswith("# Cloud Posture Scan")


@pytest.mark.asyncio
async def test_live_discover_account_produces_valid_report(
    tmp_path: Path, aws_live_account: str
) -> None:
    # discover_account=True must resolve the real current account via live STS
    contract = _live_contract(tmp_path)
    await run(contract=contract, semantic_store=None, discover_account=True, aws_region="us-east-1")
    FindingsReport.model_validate(_findings_doc(contract))


@pytest.mark.asyncio
async def test_live_findings_structure_round_trips(tmp_path: Path, aws_live_account: str) -> None:
    contract = _live_contract(tmp_path)
    await run(
        contract=contract,
        semantic_store=None,
        aws_account_id=aws_live_account,
        aws_region="us-east-1",
    )
    raw = (Path(contract.workspace) / "findings.json").read_text(encoding="utf-8")
    # parse → model → dump → re-parse: no schema drift in the live output
    report = FindingsReport.model_validate_json(raw)
    assert json.loads(report.model_dump_json())["findings"] == json.loads(raw)["findings"]


@pytest.mark.asyncio
async def test_live_degraded_marker_on_invalid_region(
    tmp_path: Path, aws_live_account: str
) -> None:
    # an invalid region must DEGRADE (Task 5), not fail the whole scan
    contract = _live_contract(tmp_path)
    await run(
        contract=contract,
        semantic_store=None,
        aws_account_id=aws_live_account,
        regions=["us-east-1", "us-bogus-1"],
    )
    summary = (Path(contract.workspace) / "summary.md").read_text(encoding="utf-8")
    assert "## Degraded regions" in summary
    assert "us-bogus-1" in summary
