"""Tests for the `compliance` CLI (Task 14)."""

from __future__ import annotations

import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from compliance.cli import main


@pytest.fixture
def shipped_cases_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="compliance",
        customer_id="cust_test",
        task="Compliance scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["read_cis_aws_benchmark"],
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


# ---------------------------- --help / --version -------------------------


def test_cli_help_lists_subcommands() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "eval" in result.output
    assert "run" in result.output


def test_cli_version_flag() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


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
            fixture: {}
            expected:
              finding_count: 99
            """
        ).strip()
    )

    result = CliRunner().invoke(main, ["eval", str(cases_dir)])
    assert result.exit_code == 1
    assert "FAIL 001_bogus" in result.output


def test_eval_missing_cases_dir_exits_nonzero(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist"
    result = CliRunner().invoke(main, ["eval", str(missing)])
    assert result.exit_code != 0


# ---------------------------- run ----------------------------------------


def test_run_with_no_inputs_emits_empty_report_and_warns(tmp_path: Path) -> None:
    contract_path = _contract_yaml(tmp_path)
    result = CliRunner().invoke(main, ["run", "--contract", str(contract_path)])
    assert result.exit_code == 0, result.output
    assert "failing controls: 0" in result.output
    assert "warning: no" in result.output
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "report.md").is_file()


def test_run_digest_lists_all_five_severity_counts(tmp_path: Path) -> None:
    contract_path = _contract_yaml(tmp_path)
    result = CliRunner().invoke(main, ["run", "--contract", str(contract_path)])
    assert "critical: 0" in result.output
    assert "high: 0" in result.output
    assert "medium: 0" in result.output
    assert "low: 0" in result.output
    assert "info: 0" in result.output


def test_run_writes_cis_attribution_footer_in_report_md(tmp_path: Path) -> None:
    """Q6 CIS Benchmarks® attribution footer must appear even on empty runs."""
    contract_path = _contract_yaml(tmp_path)
    result = CliRunner().invoke(main, ["run", "--contract", str(contract_path)])
    assert result.exit_code == 0
    md = (tmp_path / "ws" / "report.md").read_text()
    assert "CIS Benchmarks®" in md
    assert "cisecurity.org/cis-benchmarks/" in md
    assert "No verbatim CIS Securesuite text is reproduced" in md


def test_run_carries_customer_and_run_id_to_stdout(tmp_path: Path) -> None:
    contract_path = _contract_yaml(tmp_path)
    result = CliRunner().invoke(main, ["run", "--contract", str(contract_path)])
    assert "customer: cust_test" in result.output
    assert "run_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ" in result.output


def test_run_missing_contract_exits_nonzero(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["run", "--contract", str(tmp_path / "does_not_exist.yaml")])
    assert result.exit_code != 0


def test_run_help_lists_all_three_input_flags() -> None:
    result = CliRunner().invoke(main, ["run", "--help"])
    assert result.exit_code == 0
    assert "--contract" in result.output
    assert "--cloud-posture-workspace" in result.output
    assert "--data-security-workspace" in result.output


def test_run_workspace_path_echoed_in_digest(tmp_path: Path) -> None:
    contract_path = _contract_yaml(tmp_path)
    result = CliRunner().invoke(main, ["run", "--contract", str(contract_path)])
    assert f"workspace: {tmp_path / 'ws'}" in result.output


def test_run_no_inputs_omits_by_control_block(tmp_path: Path) -> None:
    """When there are zero failing controls, the by-control block is
    suppressed (no "failing controls (by CIS id):" header)."""
    contract_path = _contract_yaml(tmp_path)
    result = CliRunner().invoke(main, ["run", "--contract", str(contract_path)])
    assert "failing controls (by CIS id):" not in result.output
