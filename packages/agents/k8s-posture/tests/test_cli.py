"""Tests for the `k8s-posture` CLI."""

from __future__ import annotations

import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from k8s_posture.cli import main


@pytest.fixture
def shipped_cases_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="k8s_posture",
        customer_id="cust_test",
        task="Kubernetes posture scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["read_kube_bench", "read_polaris", "read_manifests"],
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
              kube_bench: []
              polaris: []
              manifest: []
            expected:
              finding_count: 99
            """
        ).strip()
    )

    result = CliRunner().invoke(main, ["eval", str(cases_dir)])
    assert result.exit_code == 1
    assert "FAIL 001_bogus" in result.output


def test_eval_missing_cases_dir_exits_nonzero(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["eval", str(tmp_path / "does_not_exist")])
    assert result.exit_code != 0


# ---------------------------- run ----------------------------------------


def test_run_with_no_feeds_emits_warning_and_empty_report(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    result = CliRunner().invoke(main, ["run", "--contract", str(contract)])

    assert result.exit_code == 0, result.output
    assert "warning" in result.output  # stderr captured into output
    assert "findings: 0" in result.output
    assert "agent: k8s_posture" in result.output


def test_run_writes_outputs(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    CliRunner().invoke(main, ["run", "--contract", str(contract)])
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "report.md").is_file()


def test_run_missing_contract_exits_nonzero(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["run", "--contract", str(tmp_path / "no.yaml")])
    assert result.exit_code != 0


def test_run_accepts_three_feed_flags(tmp_path: Path) -> None:
    """`--kube-bench-feed`, `--polaris-feed`, `--manifest-dir` are accepted."""
    contract = _contract_yaml(tmp_path)
    kb_feed = tmp_path / "kb.json"
    polaris_feed = tmp_path / "polaris.json"
    manifest_dir = tmp_path / "manifests"
    kb_feed.write_text("{}")
    polaris_feed.write_text("[]")
    manifest_dir.mkdir()

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--kube-bench-feed",
            str(kb_feed),
            "--polaris-feed",
            str(polaris_feed),
            "--manifest-dir",
            str(manifest_dir),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "warning" not in result.output  # all three feeds supplied


def test_run_prints_severity_breakdown(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    result = CliRunner().invoke(main, ["run", "--contract", str(contract)])
    for sev in ("critical", "high", "medium", "low", "info"):
        assert sev in result.output
