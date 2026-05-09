"""Unit tests for the Cloud Posture agent driver.

All external services are mocked: Prowler subprocess, AWS SDK, Neo4j driver,
LLM provider. The flow under test is the agent's wiring of charter +
schemas + summarizer + tool registry, not any specific external
integration.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from cloud_posture.agent import build_registry, run

# ----------------------------- fixtures --------------------------------------


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_test",
        task="Scan AWS account 111122223333 us-east-1 for posture issues",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=500,
            mb_written=10,
        ),
        permitted_tools=[
            "prowler_scan",
            "aws_s3_list_buckets",
            "aws_s3_describe",
            "aws_iam_list_users_without_mfa",
            "aws_iam_list_admin_policies",
            "kg_upsert_asset",
            "kg_upsert_finding",
        ],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _fake_prowler_findings() -> list[dict[str, Any]]:
    return [
        {
            "CheckID": "iam_user_no_mfa",
            "Severity": "high",
            "Status": "FAIL",
            "ResourceArn": "arn:aws:iam::111122223333:user/bob",
            "ResourceType": "AwsIamUser",
            "Region": "us-east-1",
            "AccountId": "111122223333",
            "StatusExtended": "User bob has no MFA",
        },
        {
            "CheckID": "s3_bucket_public_access",
            "Severity": "high",
            "Status": "FAIL",
            "ResourceArn": "arn:aws:s3:::acme-public",
            "ResourceType": "AwsS3Bucket",
            "Region": "us-east-1",
            "AccountId": "111122223333",
            "StatusExtended": "Bucket has public ACL grant",
        },
    ]


def _patch_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the four async tool wrappers with deterministic AsyncMocks."""
    from cloud_posture.tools import aws_iam, aws_s3, prowler

    async def fake_run_prowler_aws(**_kwargs: Any) -> prowler.ProwlerResult:
        return prowler.ProwlerResult(raw_findings=_fake_prowler_findings())

    monkeypatch.setattr(prowler, "run_prowler_aws", fake_run_prowler_aws)
    monkeypatch.setattr(aws_s3, "list_buckets", AsyncMock(return_value=[]))
    monkeypatch.setattr(
        aws_iam,
        "list_users_without_mfa",
        AsyncMock(return_value=["bob"]),
    )
    monkeypatch.setattr(
        aws_iam,
        "list_admin_policies",
        AsyncMock(
            return_value=[
                {
                    "policy_name": "TooBroad",
                    "policy_arn": "arn:aws:iam::111122223333:policy/TooBroad",
                    "document": {
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                    },
                }
            ]
        ),
    )


def _make_neo4j() -> MagicMock:
    """Mocked async Neo4j driver: `async with driver.session() as s: await s.run(...)`."""
    session = MagicMock()
    session.run = AsyncMock()
    driver = MagicMock()
    driver.session.return_value.__aenter__ = AsyncMock(return_value=session)
    driver.session.return_value.__aexit__ = AsyncMock(return_value=None)
    return driver


# ----------------------------- registry --------------------------------------


def test_build_registry_registers_all_seven_tools() -> None:
    registry = build_registry(neo4j_driver=_make_neo4j(), customer_id="cust_x")
    expected = {
        "prowler_scan",
        "aws_s3_list_buckets",
        "aws_s3_describe",
        "aws_iam_list_users_without_mfa",
        "aws_iam_list_admin_policies",
        "kg_upsert_asset",
        "kg_upsert_finding",
    }
    assert expected.issubset(set(registry.known_tools()))


def test_build_registry_is_callable_without_neo4j_driver() -> None:
    """KG tools are not registered when neo4j_driver is None."""
    registry = build_registry(neo4j_driver=None, customer_id="cust_x")
    assert "prowler_scan" in registry.known_tools()
    assert "kg_upsert_asset" not in registry.known_tools()
    assert "kg_upsert_finding" not in registry.known_tools()


# ----------------------------- run() ----------------------------------------


@pytest.mark.asyncio
async def test_run_writes_findings_json_and_summary_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)

    report = await run(contract=contract, neo4j_driver=_make_neo4j())

    workspace = Path(contract.workspace)
    assert (workspace / "findings.json").exists()
    assert (workspace / "summary.md").exists()
    assert (workspace / "audit.jsonl").exists()
    assert report.total >= 2


@pytest.mark.asyncio
async def test_run_findings_are_ocsf_compliance_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)

    await run(contract=contract, neo4j_driver=_make_neo4j())

    findings_doc = json.loads((Path(contract.workspace) / "findings.json").read_text())
    assert findings_doc["agent"] == "cloud_posture"
    assert findings_doc["customer_id"] == "cust_test"
    assert isinstance(findings_doc["findings"], list)
    for raw in findings_doc["findings"]:
        assert raw["category_uid"] == 2  # OCSF Findings
        assert raw["class_uid"] == 2003  # Compliance Finding
        assert "nexus_envelope" in raw
        envelope = raw["nexus_envelope"]
        assert envelope["tenant_id"] == "cust_test"
        assert envelope["agent_id"] == "cloud_posture"
        assert envelope["charter_invocation_id"] == contract.delegation_id


@pytest.mark.asyncio
async def test_run_summary_groups_by_severity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)

    await run(contract=contract, neo4j_driver=_make_neo4j())

    summary = (Path(contract.workspace) / "summary.md").read_text()
    assert "# Cloud Posture Scan" in summary
    assert "**Critical**:" in summary
    assert "**High**:" in summary
    assert "Total findings:" in summary


@pytest.mark.asyncio
async def test_run_emits_full_audit_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)

    await run(contract=contract, neo4j_driver=_make_neo4j())

    actions = [
        json.loads(line)["action"]
        for line in (Path(contract.workspace) / "audit.jsonl").read_text().splitlines()
    ]
    assert actions[0] == "invocation_started"
    assert actions[-1] == "invocation_completed"
    assert "tool_call" in actions
    assert "output_written" in actions


@pytest.mark.asyncio
async def test_run_skips_kg_when_neo4j_driver_is_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent must still produce findings.json + summary.md without a graph."""
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)

    report = await run(contract=contract, neo4j_driver=None)

    assert report.total >= 2
    assert (Path(contract.workspace) / "findings.json").exists()
    assert (Path(contract.workspace) / "summary.md").exists()


@pytest.mark.asyncio
async def test_run_handles_empty_prowler_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Agent produces a valid (empty-ish) report when no Prowler / IAM findings."""
    contract = _contract(tmp_path)

    from cloud_posture.tools import aws_iam, aws_s3, prowler

    async def fake_run_prowler_aws(**_kwargs: Any) -> prowler.ProwlerResult:
        return prowler.ProwlerResult(raw_findings=[])

    monkeypatch.setattr(prowler, "run_prowler_aws", fake_run_prowler_aws)
    monkeypatch.setattr(aws_s3, "list_buckets", AsyncMock(return_value=[]))
    monkeypatch.setattr(aws_iam, "list_users_without_mfa", AsyncMock(return_value=[]))
    monkeypatch.setattr(aws_iam, "list_admin_policies", AsyncMock(return_value=[]))

    report = await run(contract=contract, neo4j_driver=None)
    assert report.total == 0

    summary = (Path(contract.workspace) / "summary.md").read_text()
    assert "No findings detected" in summary


@pytest.mark.asyncio
async def test_run_iam_no_mfa_finding_has_correct_id_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)

    await run(contract=contract, neo4j_driver=_make_neo4j())

    findings_doc = json.loads((Path(contract.workspace) / "findings.json").read_text())
    finding_uids = {f["finding_info"]["uid"] for f in findings_doc["findings"]}
    # We seeded one user "bob" with no MFA → expect the corresponding finding.
    assert any(uid == "CSPM-AWS-IAM-001-bob" for uid in finding_uids)


@pytest.mark.asyncio
async def test_run_admin_policy_finding_is_critical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)

    await run(contract=contract, neo4j_driver=_make_neo4j())

    findings_doc = json.loads((Path(contract.workspace) / "findings.json").read_text())
    admin = next(
        f
        for f in findings_doc["findings"]
        if f["finding_info"]["uid"].startswith("CSPM-AWS-IAM-002-")
    )
    assert admin["severity_id"] == 5  # Critical
