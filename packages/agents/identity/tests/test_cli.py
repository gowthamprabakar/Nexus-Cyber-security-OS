"""Tests for the `identity-agent` CLI."""

from __future__ import annotations

import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from identity import agent as agent_mod
from identity.cli import main
from identity.tools.aws_iam import IdentityListing


@pytest.fixture
def shipped_cases_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="identity",
        customer_id="cust_test",
        task="Scan AWS account 123456789012 identity posture",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=200,
            mb_written=10,
        ),
        permitted_tools=[
            "aws_iam_list_identities",
            "aws_iam_simulate_principal_policy",
            "aws_access_analyzer_findings",
        ],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(contract.model_dump(mode="json")))
    return path


# ---------------------------- --help -------------------------------------


def test_cli_help_lists_subcommands() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "eval" in result.output
    assert "run" in result.output


def test_cli_version_flag() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


# ---------------------------- eval ---------------------------------------


def test_eval_with_shipped_cases_passes_10_of_10(shipped_cases_dir: Path) -> None:
    """The shipped 10 YAML cases all pass — same gate as test_eval_runner.py."""
    result = CliRunner().invoke(main, ["eval", str(shipped_cases_dir)])
    assert result.exit_code == 0, result.output
    assert "10/10 passed" in result.output


def test_eval_exits_nonzero_on_failure(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "001_bogus.yaml").write_text(
        textwrap.dedent(
            """
            case_id: 001_bogus
            description: deliberately wrong expectation
            fixture:
              iam_listing: {users: [], roles: [], groups: []}
            expected:
              finding_count: 99
            """
        )
    )
    result = CliRunner().invoke(main, ["eval", str(cases_dir)])
    assert result.exit_code == 1
    assert "0/1 passed" in result.output
    assert "FAIL 001_bogus" in result.output


# ---------------------------- run ----------------------------------------


def test_run_subcommand_prints_summary(tmp_path: Path) -> None:
    """`run` against an empty-account contract prints the agent + finding digest."""

    async def fake_list(**_: Any) -> IdentityListing:
        return IdentityListing(users=(), roles=(), groups=())

    with patch.object(agent_mod, "aws_iam_list_identities", fake_list):
        result = CliRunner().invoke(main, ["run", "--contract", str(_contract_yaml(tmp_path))])

    assert result.exit_code == 0, result.output
    assert "agent: identity" in result.output
    assert "customer: cust_test" in result.output
    assert "findings: 0" in result.output
    assert "overprivilege: 0" in result.output


def test_run_writes_findings_and_summary_to_workspace(tmp_path: Path) -> None:
    async def fake_list(**_: Any) -> IdentityListing:
        return IdentityListing(users=(), roles=(), groups=())

    contract_path = _contract_yaml(tmp_path)
    with patch.object(agent_mod, "aws_iam_list_identities", fake_list):
        CliRunner().invoke(main, ["run", "--contract", str(contract_path)])

    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "summary.md").is_file()


def test_run_threads_mfa_users_into_agent(tmp_path: Path) -> None:
    """`--mfa-user` flags must reach the agent's users_with_mfa set."""
    captured: dict[str, Any] = {}

    async def fake_list(**_: Any) -> IdentityListing:
        return IdentityListing(users=(), roles=(), groups=())

    real_run = agent_mod.run

    async def captured_run(*args: Any, **kwargs: Any) -> Any:
        captured["users_with_mfa"] = kwargs.get("users_with_mfa")
        return await real_run(*args, **kwargs)

    with (
        patch.object(agent_mod, "aws_iam_list_identities", fake_list),
        patch("identity.cli.agent_run", captured_run),
    ):
        result = CliRunner().invoke(
            main,
            [
                "run",
                "--contract",
                str(_contract_yaml(tmp_path)),
                "--mfa-user",
                "alice",
                "--mfa-user",
                "bob",
            ],
        )

    assert result.exit_code == 0, result.output
    assert captured["users_with_mfa"] == frozenset({"alice", "bob"})
