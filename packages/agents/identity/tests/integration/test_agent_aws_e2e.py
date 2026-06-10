"""D.2 v0.2 Task 18 — live end-to-end AWS IAM pipeline (WI-I4 HARD).

Two layers, mirroring D.1's WI-V6 standard:

- ``test_full_pipeline_against_moto`` — the **real** pipeline wired end-to-end and
  run on every push: `CredentialResolver` → boto3 (moto) → live IAM enumeration →
  effective-grant synthesis → OCSF 2004 emission → workspace artifacts. No faked
  listing seam — this is the wiring proof.
- ``test_live_e2e_against_real_account`` — the genuine pipeline against a real AWS
  account, gated by `NEXUS_LIVE_IDENTITY_AWS` (operator-run; skipped in CI).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import boto3
import pytest
from charter.contract import BudgetSpec, ExecutionContract
from identity.agent import run
from moto import mock_aws

_ADMIN_DOC = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="identity",
        customer_id="cust_test",
        task="Live identity posture scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=500,
            mb_written=10,
        ),
        permitted_tools=[
            "aws_iam_list_identities",
            "aws_iam_simulate_principal_policy",
            "aws_access_analyzer_findings",
        ],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


@pytest.mark.asyncio
async def test_full_pipeline_against_moto(tmp_path: Path) -> None:
    """WI-I4 wiring proof: the whole pipeline, no faked listing — run on every push."""
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        admin = iam.create_policy(PolicyName="AdministratorAccess", PolicyDocument=_ADMIN_DOC)[
            "Policy"
        ]["Arn"]
        iam.create_user(UserName="alice")
        iam.attach_user_policy(UserName="alice", PolicyArn=admin)

        report = await run(_contract(tmp_path))

    # The report came from the REAL enumeration: resolver → moto IAM → list →
    # grant synthesis → normalize → emit (not a patched listing).
    assert report.total >= 1
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "summary.md").is_file()

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in payload["findings"]}
    assert "overprivilege" in types  # alice's AdministratorAccess flowed through end-to-end
    # the finding names the principal actually enumerated from the account
    assert any("alice" in json.dumps(f).lower() for f in payload["findings"])


@pytest.mark.asyncio
async def test_live_e2e_against_real_account(aws_identity_live: None, tmp_path: Path) -> None:
    """WI-I4 live proof: the genuine pipeline against a real AWS account.

    Skipped unless `NEXUS_LIVE_IDENTITY_AWS=1` and live AWS is reachable. We do not
    assert specific findings against an unknown account — only that the full pipeline
    ran and produced a well-formed report + artifacts.
    """
    report = await run(_contract(tmp_path), profile=os.environ.get("AWS_PROFILE"))

    assert report.agent == "identity"
    assert report.customer_id == "cust_test"
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "summary.md").is_file()
