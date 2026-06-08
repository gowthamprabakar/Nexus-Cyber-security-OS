"""F.3 v0.2 Task 4 — region-scoping tests (per-region Prowler, global-once IAM)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from cloud_posture import cli
from cloud_posture.agent import run
from cloud_posture.tools import aws_account_discovery, aws_iam, aws_s3, prowler


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
            # generous so multi-region tests exercise region threading, not the
            # cloud-call budget (prowler is ~200 cloud_calls/region; real
            # multi-region scans must size their contract budget accordingly).
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


def _empty_prowler() -> AsyncMock:
    return AsyncMock(return_value=prowler.ProwlerResult(raw_findings=[]))


def _patch_tools(
    monkeypatch: pytest.MonkeyPatch,
    *,
    prowler_mock: AsyncMock,
    users: AsyncMock | None = None,
    admin: AsyncMock | None = None,
) -> tuple[AsyncMock, AsyncMock]:
    users = users or AsyncMock(return_value=[])
    admin = admin or AsyncMock(return_value=[])
    monkeypatch.setattr(prowler, "run_prowler_aws", prowler_mock)
    monkeypatch.setattr(aws_iam, "list_users_without_mfa", users)
    monkeypatch.setattr(aws_iam, "list_admin_policies", admin)
    monkeypatch.setattr(aws_s3, "list_buckets", AsyncMock(return_value=[]))
    return users, admin


def _scanned_regions(prowler_mock: AsyncMock) -> list[str]:
    return [call.kwargs["region"] for call in prowler_mock.call_args_list]


# ---------------------- agent: region threading -----------------------------


@pytest.mark.asyncio
async def test_explicit_regions_scan_prowler_once_each(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pm = _empty_prowler()
    _patch_tools(monkeypatch, prowler_mock=pm)
    await run(contract=_contract(tmp_path), semantic_store=None, regions=["us-east-1", "eu-west-1"])
    assert pm.call_count == 2
    assert sorted(_scanned_regions(pm)) == ["eu-west-1", "us-east-1"]


@pytest.mark.asyncio
async def test_default_scopes_to_single_aws_region(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pm = _empty_prowler()
    _patch_tools(monkeypatch, prowler_mock=pm)
    await run(contract=_contract(tmp_path), semantic_store=None, aws_region="ap-south-1")
    assert pm.call_count == 1
    assert _scanned_regions(pm) == ["ap-south-1"]


@pytest.mark.asyncio
async def test_discover_all_regions_scans_each_discovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pm = _empty_prowler()
    _patch_tools(monkeypatch, prowler_mock=pm)
    discover = AsyncMock(return_value=["us-east-1", "us-west-2", "eu-west-1"])
    monkeypatch.setattr(aws_account_discovery, "discover_regions", discover)
    await run(contract=_contract(tmp_path), semantic_store=None, discover_all_regions=True)
    assert discover.call_count == 1  # consumes the Task-3 discovery tool
    assert pm.call_count == 3
    assert sorted(_scanned_regions(pm)) == ["eu-west-1", "us-east-1", "us-west-2"]


@pytest.mark.asyncio
async def test_explicit_regions_win_over_discover_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pm = _empty_prowler()
    _patch_tools(monkeypatch, prowler_mock=pm)
    discover = AsyncMock(return_value=["everything"])
    monkeypatch.setattr(aws_account_discovery, "discover_regions", discover)
    await run(
        contract=_contract(tmp_path),
        semantic_store=None,
        regions=["us-east-1"],
        discover_all_regions=True,
    )
    discover.assert_not_called()
    assert _scanned_regions(pm) == ["us-east-1"]


@pytest.mark.asyncio
async def test_iam_called_once_regardless_of_region_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pm = _empty_prowler()
    users, admin = _patch_tools(monkeypatch, prowler_mock=pm)
    await run(
        contract=_contract(tmp_path),
        semantic_store=None,
        regions=["us-east-1", "eu-west-1", "ap-south-1"],
    )
    assert pm.call_count == 3
    assert users.call_count == 1  # IAM is global — once, not per region
    assert admin.call_count == 1


@pytest.mark.asyncio
async def test_findings_aggregated_across_regions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def finding(region: str) -> dict[str, Any]:
        return {
            "CheckID": "s3_bucket_public_access",
            "ResourceArn": f"arn:aws:s3:::bucket-{region}",
            "AccountId": "111122223333",
            "Region": region,
            "ResourceType": "AwsS3Bucket",
            "Severity": "high",
            "StatusExtended": "public",
        }

    pm = AsyncMock(
        side_effect=[
            prowler.ProwlerResult(raw_findings=[finding("us-east-1")]),
            prowler.ProwlerResult(raw_findings=[finding("eu-west-1")]),
        ]
    )
    _patch_tools(monkeypatch, prowler_mock=pm)
    report = await run(
        contract=_contract(tmp_path),
        semantic_store=None,
        regions=["us-east-1", "eu-west-1"],
    )
    blob = json.dumps(report.findings)
    assert "bucket-us-east-1" in blob
    assert "bucket-eu-west-1" in blob
    assert report.total >= 2


# ---------------------- CLI: --regions parsing ------------------------------


def _fake_report() -> MagicMock:
    report = MagicMock()
    report.agent = "cloud_posture"
    report.agent_version = "0.2.0"
    report.customer_id = "cust"
    report.run_id = "run-1"
    report.total = 0
    report.count_by_severity.return_value = {}
    return report


def _invoke(args: list[str]) -> tuple[Any, AsyncMock]:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("contract.yaml").write_text("placeholder")
        with (
            patch.object(cli, "load_contract", return_value=MagicMock(workspace=Path("."))),
            patch.object(cli, "agent_run", new=AsyncMock(return_value=_fake_report())) as ar,
        ):
            result = runner.invoke(cli.main, ["run", "--contract", "contract.yaml", *args])
    return result, ar


def test_cli_regions_parses_comma_separated_list() -> None:
    result, ar = _invoke(["--regions", "us-east-1, eu-west-1"])
    assert result.exit_code == 0, result.output
    assert ar.call_args.kwargs.get("regions") == ["us-east-1", "eu-west-1"]
    assert ar.call_args.kwargs.get("discover_all_regions") is False


def test_cli_omitting_regions_discovers_all() -> None:
    result, ar = _invoke([])
    assert result.exit_code == 0, result.output
    assert ar.call_args.kwargs.get("regions") is None
    assert ar.call_args.kwargs.get("discover_all_regions") is True


def test_cli_single_region() -> None:
    result, ar = _invoke(["--regions", "us-west-2"])
    assert result.exit_code == 0, result.output
    assert ar.call_args.kwargs.get("regions") == ["us-west-2"]
    assert ar.call_args.kwargs.get("discover_all_regions") is False
