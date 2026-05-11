"""Tests for the `runtime-threat-agent` CLI."""

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from runtime_threat.cli import main


@pytest.fixture
def shipped_cases_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="runtime_threat",
        customer_id="cust_test",
        task="Runtime threat scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["falco_alerts_read", "tracee_alerts_read", "osquery_run"],
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
              falco_alerts: []
              tracee_alerts: []
              osquery_rows: []
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


def test_run_subcommand_warns_when_no_feeds_supplied(tmp_path: Path) -> None:
    """No --falco-feed / --tracee-feed / --osquery-pack → warning + empty report."""
    result = CliRunner().invoke(main, ["run", "--contract", str(_contract_yaml(tmp_path))])
    assert result.exit_code == 0, result.output
    assert "warning: no --falco-feed" in result.output
    assert "agent: runtime_threat" in result.output
    assert "findings: 0" in result.output


def test_run_writes_findings_and_summary_to_workspace(tmp_path: Path) -> None:
    contract_path = _contract_yaml(tmp_path)
    CliRunner().invoke(main, ["run", "--contract", str(contract_path)])

    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "summary.md").is_file()


def test_run_with_falco_feed_emits_finding(tmp_path: Path) -> None:
    """A real Falco JSONL feed end-to-end (no monkeypatch — the reader is invoked)."""
    feed = tmp_path / "falco.jsonl"
    feed.write_text(
        json.dumps(
            {
                "time": "2026-05-11T12:00:00Z",
                "rule": "Terminal shell in container",
                "priority": "Critical",
                "output": "shell spawned",
                "output_fields": {"container.id": "abc123def456"},
                "tags": ["container", "shell", "process"],
            }
        )
        + "\n"
    )

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(_contract_yaml(tmp_path)),
            "--falco-feed",
            str(feed),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "findings: 1" in result.output
    assert "runtime_process: 1" in result.output
    assert "critical: 1" in result.output


def test_run_finding_type_breakdown_in_digest(tmp_path: Path) -> None:
    """Empty run still prints the five-family breakdown."""
    result = CliRunner().invoke(main, ["run", "--contract", str(_contract_yaml(tmp_path))])
    for ft in (
        "runtime_process",
        "runtime_file",
        "runtime_network",
        "runtime_syscall",
        "runtime_osquery",
    ):
        assert f"{ft}: 0" in result.output
