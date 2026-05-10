"""LocalStack integration tests for the Cloud Posture agent.

These exercise the agent end-to-end against LocalStack-backed boto3 calls
— the unit tests in `test_agent_unit.py` only mock the AWS SDK and can't
catch wire-format regressions or async + thread interaction issues.

Prowler is mocked here because LocalStack does not host a Prowler binary;
the IAM and S3 SDK calls hit LocalStack for real.

Skipped by default. Enable with `NEXUS_LIVE_LOCALSTACK=1`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3
import pytest
from charter.contract import BudgetSpec, ExecutionContract
from cloud_posture.agent import run

pytestmark = pytest.mark.integration

# moto fixture password reused so ruff's S106 (hardcoded password) flags
# only this single line in this file.
_FAKE_PASSWORD = "P@ssw0rd!Strong!"  # noqa: S105 — LocalStack-only

_TOO_BROAD_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_localstack_integration",
        task="Scan the LocalStack-backed AWS account for posture issues",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=120.0,
            cloud_api_calls=500,
            mb_written=10,
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
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _stub_prowler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Prowler subprocess wrapper with an empty-result async stub.

    LocalStack doesn't host a Prowler binary; this test focuses on the
    SDK-driven IAM enrichment paths.
    """
    from cloud_posture.tools import prowler

    async def fake_run_prowler_aws(**_kwargs: Any) -> prowler.ProwlerResult:
        return prowler.ProwlerResult(raw_findings=[])

    monkeypatch.setattr(prowler, "run_prowler_aws", fake_run_prowler_aws)


@pytest.mark.asyncio
async def test_iam_no_mfa_detected_against_localstack(
    tmp_path: Path,
    aws_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two IAM users; only one has MFA. Expect exactly one no-MFA finding."""
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="alice", Password=_FAKE_PASSWORD)
    iam.create_login_profile(UserName="bob", Password=_FAKE_PASSWORD)
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="alice")
    iam.enable_mfa_device(
        UserName="alice",
        SerialNumber=device["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    _stub_prowler(monkeypatch)

    contract = _contract(tmp_path)
    report = await run(contract=contract, neo4j_driver=None)

    findings_doc = json.loads((Path(contract.workspace) / "findings.json").read_text())
    no_mfa_uids = {
        f["finding_info"]["uid"]
        for f in findings_doc["findings"]
        if f["finding_info"]["uid"].startswith("CSPM-AWS-IAM-001-")
    }
    assert "CSPM-AWS-IAM-001-bob" in no_mfa_uids
    assert "CSPM-AWS-IAM-001-alice" not in no_mfa_uids
    assert report.total >= 1


@pytest.mark.asyncio
async def test_admin_policy_detected_against_localstack(
    tmp_path: Path,
    aws_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A customer-managed policy with Action=* Resource=* must produce a Critical."""
    iam = boto3.client("iam")
    iam.create_policy(PolicyName="TooBroad", PolicyDocument=_TOO_BROAD_DOC)

    _stub_prowler(monkeypatch)

    contract = _contract(tmp_path)
    await run(contract=contract, neo4j_driver=None)

    findings_doc = json.loads((Path(contract.workspace) / "findings.json").read_text())
    admin = next(
        (
            f
            for f in findings_doc["findings"]
            if f["finding_info"]["uid"].startswith("CSPM-AWS-IAM-002-")
        ),
        None,
    )
    assert admin is not None
    assert admin["severity_id"] == 5  # Critical
    assert admin["compliance"]["control"] == "CSPM-AWS-IAM-002"


@pytest.mark.asyncio
async def test_clean_account_emits_no_findings(
    tmp_path: Path,
    aws_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A LocalStack environment with no console users / admin policies emits zero findings."""
    _stub_prowler(monkeypatch)

    contract = _contract(tmp_path)
    report = await run(contract=contract, neo4j_driver=None)

    assert report.total == 0
    summary = (Path(contract.workspace) / "summary.md").read_text()
    assert "No findings detected" in summary
