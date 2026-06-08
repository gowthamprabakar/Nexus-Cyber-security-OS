"""F.3 v0.2 Task 5 — live-AWS error handling + partial-scan degradation tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from botocore.exceptions import ClientError
from charter.contract import BudgetSpec, ExecutionContract
from charter.exceptions import BudgetExhausted
from cloud_posture.agent import run
from cloud_posture.tools import aws_iam, aws_s3, prowler
from cloud_posture.tools.prowler import ProwlerError


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_test",
        task="Scan for posture issues",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=100_000,
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


def _patch_iam_s3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aws_iam, "list_users_without_mfa", AsyncMock(return_value=[]))
    monkeypatch.setattr(aws_iam, "list_admin_policies", AsyncMock(return_value=[]))
    monkeypatch.setattr(aws_s3, "list_buckets", AsyncMock(return_value=[]))


def _ok(region: str) -> prowler.ProwlerResult:
    return prowler.ProwlerResult(
        raw_findings=[
            {
                "CheckID": "s3_bucket_public_access",
                "ResourceArn": f"arn:aws:s3:::bucket-{region}",
                "AccountId": "111122223333",
                "Region": region,
                "ResourceType": "AwsS3Bucket",
                "Severity": "high",
                "StatusExtended": "public",
            }
        ]
    )


def _throttle(secret: str = "") -> ClientError:
    return ClientError(
        {"Error": {"Code": "Throttling", "Message": f"Rate exceeded {secret}"}},
        "DescribeRegions",
    )


def _summary(contract: ExecutionContract) -> str:
    return (Path(contract.workspace) / "summary.md").read_text(encoding="utf-8")


# ---------------------- partial-scan degradation ----------------------------


@pytest.mark.asyncio
async def test_single_region_failure_degrades_and_run_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_iam_s3(monkeypatch)
    monkeypatch.setattr(prowler, "run_prowler_aws", AsyncMock(side_effect=ProwlerError("boom")))
    # does NOT raise — a failed region degrades, it does not fail the run
    report = await run(contract=contract, semantic_store=None, regions=["us-east-1"])
    assert report.total == 0
    assert "## Degraded regions" in _summary(contract)
    assert "us-east-1" in _summary(contract)


@pytest.mark.asyncio
async def test_multi_region_partial_failure_others_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_iam_s3(monkeypatch)
    monkeypatch.setattr(
        prowler,
        "run_prowler_aws",
        AsyncMock(side_effect=[_ok("us-east-1"), ProwlerError("boom"), _ok("ap-south-1")]),
    )
    report = await run(
        contract=contract,
        semantic_store=None,
        regions=["us-east-1", "eu-west-1", "ap-south-1"],
    )
    # the two healthy regions produced findings; the failed one is degraded
    assert report.total == 2
    summary = _summary(contract)
    assert "bucket-us-east-1" in summary
    assert "bucket-ap-south-1" in summary
    assert "eu-west-1" in summary  # degraded marker


@pytest.mark.asyncio
async def test_no_degraded_section_when_all_regions_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_iam_s3(monkeypatch)
    monkeypatch.setattr(prowler, "run_prowler_aws", AsyncMock(side_effect=[_ok("us-east-1")]))
    await run(contract=contract, semantic_store=None, regions=["us-east-1"])
    assert "Degraded regions" not in _summary(contract)  # byte-identity guard


# ---------------------- error-shape guarantees ------------------------------


@pytest.mark.asyncio
async def test_clienterror_surfaces_aws_error_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_iam_s3(monkeypatch)
    monkeypatch.setattr(prowler, "run_prowler_aws", AsyncMock(side_effect=_throttle()))
    await run(contract=contract, semantic_store=None, regions=["us-east-1"])
    assert "ClientError: Throttling" in _summary(contract)


@pytest.mark.asyncio
async def test_throttle_is_degraded_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_iam_s3(monkeypatch)
    monkeypatch.setattr(prowler, "run_prowler_aws", AsyncMock(side_effect=_throttle()))
    report = await run(contract=contract, semantic_store=None, regions=["us-east-1"])
    assert report.total == 0  # completed, did not raise


@pytest.mark.asyncio
async def test_error_message_contains_no_secret_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_key = "AKIAIOSFODNN7EXAMPLE"  # canonical example access-key id, not real
    contract = _contract(tmp_path)
    _patch_iam_s3(monkeypatch)
    monkeypatch.setattr(
        prowler,
        "run_prowler_aws",
        AsyncMock(side_effect=ProwlerError(f"creds {fake_key} leaked in the error")),
    )
    await run(contract=contract, semantic_store=None, regions=["us-east-1"])
    summary = _summary(contract)
    assert fake_key not in summary  # the raw message (with the key) is never surfaced
    assert "ProwlerError" in summary  # only the safe type name is


@pytest.mark.asyncio
async def test_no_traceback_or_raw_message_in_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_iam_s3(monkeypatch)
    monkeypatch.setattr(
        prowler,
        "run_prowler_aws",
        AsyncMock(side_effect=ProwlerError("prowler exited 2: detailed internal trace path")),
    )
    summary = ""
    await run(contract=contract, semantic_store=None, regions=["us-east-1"])
    summary = _summary(contract)
    assert "Traceback" not in summary
    assert "detailed internal trace path" not in summary  # raw message withheld


@pytest.mark.asyncio
async def test_eventual_consistency_transient_error_degrades(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transient = ClientError(
        {"Error": {"Code": "InvalidClientTokenId", "Message": "token not yet valid"}},
        "GetCallerIdentity",
    )
    contract = _contract(tmp_path)
    _patch_iam_s3(monkeypatch)
    monkeypatch.setattr(
        prowler,
        "run_prowler_aws",
        AsyncMock(side_effect=[transient, _ok("eu-west-1")]),
    )
    report = await run(contract=contract, semantic_store=None, regions=["us-east-1", "eu-west-1"])
    assert report.total == 1  # the healthy region still completed
    assert "ClientError: InvalidClientTokenId" in _summary(contract)


# ---------------------- budget is a hard stop -------------------------------


@pytest.mark.asyncio
async def test_budget_exhausted_is_a_hard_stop_not_degraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _contract(tmp_path)
    _patch_iam_s3(monkeypatch)
    monkeypatch.setattr(
        prowler,
        "run_prowler_aws",
        AsyncMock(side_effect=BudgetExhausted(dimension="cloud_api_calls", limit=1, used=2)),
    )
    with pytest.raises(BudgetExhausted):
        await run(contract=contract, semantic_store=None, regions=["us-east-1"])
