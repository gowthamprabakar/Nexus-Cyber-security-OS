"""F.3 v0.2 Task 3 — aws_account_discovery (STS identity + region enum) tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from cloud_posture import cli
from cloud_posture.credentials import CredentialResolver
from cloud_posture.tools import aws_account_discovery

# ---------------------- discover_account_id (STS) ---------------------------


@pytest.mark.asyncio
async def test_discover_account_id_returns_current_account() -> None:
    resolver = MagicMock(spec=CredentialResolver)
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "999988887777", "Arn": "arn:…"}
    resolver.client.return_value = sts
    assert await aws_account_discovery.discover_account_id(resolver) == "999988887777"


@pytest.mark.asyncio
async def test_discover_account_id_queries_sts() -> None:
    resolver = MagicMock(spec=CredentialResolver)
    resolver.client.return_value.get_caller_identity.return_value = {"Account": "1"}
    await aws_account_discovery.discover_account_id(resolver)
    resolver.client.assert_called_once_with("sts")


@pytest.mark.asyncio
async def test_discover_account_id_coerces_to_str() -> None:
    resolver = MagicMock(spec=CredentialResolver)
    resolver.client.return_value.get_caller_identity.return_value = {"Account": 123456789012}
    out = await aws_account_discovery.discover_account_id(resolver)
    assert out == "123456789012"
    assert isinstance(out, str)


# ---------------------- discover_regions ------------------------------------


@pytest.mark.asyncio
async def test_discover_regions_returns_enumerated_regions() -> None:
    resolver = MagicMock(spec=CredentialResolver)
    resolver.resolve_session.return_value.get_available_regions.return_value = [
        "us-east-1",
        "eu-west-1",
    ]
    assert await aws_account_discovery.discover_regions(resolver) == ["us-east-1", "eu-west-1"]


@pytest.mark.asyncio
async def test_discover_regions_queries_ec2_partition() -> None:
    resolver = MagicMock(spec=CredentialResolver)
    session = resolver.resolve_session.return_value
    session.get_available_regions.return_value = []
    await aws_account_discovery.discover_regions(resolver)
    session.get_available_regions.assert_called_once_with("ec2")


@pytest.mark.asyncio
async def test_discover_regions_returns_a_copy() -> None:
    resolver = MagicMock(spec=CredentialResolver)
    src = ["us-east-1"]
    resolver.resolve_session.return_value.get_available_regions.return_value = src
    out = await aws_account_discovery.discover_regions(resolver)
    assert out == src
    assert out is not src  # a fresh list — safe to mutate downstream


def test_current_account_only_no_cross_account_apis() -> None:
    """Q4 lock: current-account only — no AssumeRole / Organizations here."""
    source = Path(aws_account_discovery.__file__).read_text(encoding="utf-8")
    # tolerate the docstring's prose mentions; assert no API *calls* by name.
    for forbidden in ("assume_role(", "list_accounts(", ".AssumeRole"):
        assert forbidden not in source, f"Q4 violation: {forbidden} present"


# ---------------------- CLI: --aws-account-id → discover --------------------


def _fake_report() -> MagicMock:
    report = MagicMock()
    report.agent = "cloud_posture"
    report.agent_version = "0.2.0"
    report.customer_id = "cust"
    report.run_id = "run-1"
    report.total = 0
    report.count_by_severity.return_value = {}
    return report


def test_cli_discovers_account_when_omitted() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("contract.yaml").write_text("placeholder")
        with (
            patch.object(cli, "load_contract", return_value=MagicMock(workspace=Path("."))),
            patch.object(cli, "agent_run", new=AsyncMock(return_value=_fake_report())) as ar,
        ):
            result = runner.invoke(cli.main, ["run", "--contract", "contract.yaml"])
        assert result.exit_code == 0, result.output
        assert ar.call_args.kwargs.get("discover_account") is True
        assert ar.call_args.kwargs.get("aws_account_id") is None


def test_cli_explicit_account_disables_discovery() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("contract.yaml").write_text("placeholder")
        with (
            patch.object(cli, "load_contract", return_value=MagicMock(workspace=Path("."))),
            patch.object(cli, "agent_run", new=AsyncMock(return_value=_fake_report())) as ar,
        ):
            result = runner.invoke(
                cli.main,
                ["run", "--contract", "contract.yaml", "--aws-account-id", "123456789012"],
            )
        assert result.exit_code == 0, result.output
        assert ar.call_args.kwargs.get("discover_account") is False
        assert ar.call_args.kwargs.get("aws_account_id") == "123456789012"
