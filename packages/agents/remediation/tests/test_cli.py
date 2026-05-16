"""Tests for the `remediation` CLI.

Two subcommands (eval / run) and the mutual-exclusion + mode-escalation gates
they surface as `click.UsageError`.
"""

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from remediation.cli import main


@pytest.fixture
def shipped_cases_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="remediation",
        customer_id="cust_test",
        task="Remediation v0.1 CLI test",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=20,
            mb_written=10,
        ),
        permitted_tools=["read_findings", "apply_patch"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(contract.model_dump(mode="json")))
    return path


def _empty_findings_json(tmp_path: Path) -> Path:
    """Write a D.6-shaped `findings.json` with zero records.

    The agent's Stage-1 ingest tolerates an empty array; recommend-mode runs
    against this need no D.6 detector or kubectl mocking.
    """
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps(
            {
                "agent": "k8s_posture",
                "agent_version": "0.3.0",
                "customer_id": "cust_test",
                "run_id": "test-run",
                "scan_started_at": datetime.now(UTC).isoformat(),
                "scan_completed_at": datetime.now(UTC).isoformat(),
                "findings": [],
            }
        )
    )
    return path


def _auth_yaml(tmp_path: Path, **fields: object) -> Path:
    path = tmp_path / "auth.yaml"
    path.write_text(yaml.safe_dump(fields))
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
    """Same gate as the test_eval_runner.py 10/10 acceptance test, via CLI."""
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
              mode: recommend
              authorization:
                mode_recommend_authorized: true
              findings: []
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


# ---------------------------- run: recommend mode (no cluster) -----------


def test_run_recommend_mode_no_cluster_needed(tmp_path: Path) -> None:
    """Recommend mode is the only one that runs without --kubeconfig/--in-cluster."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    auth = _auth_yaml(tmp_path, mode_recommend_authorized=True)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--mode",
            "recommend",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "mode: recommend" in result.output
    assert "findings: 0" in result.output


def test_run_default_mode_is_recommend(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "mode: recommend" in result.output


def test_run_writes_required_outputs(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
        ],
    )
    workspace = tmp_path / "ws"
    assert (workspace / "findings.json").is_file()
    assert (workspace / "report.md").is_file()
    assert (workspace / "audit.jsonl").is_file()


# ---------------------------- run: mutual-exclusion gates ---------------


def test_run_refuses_both_kubeconfig_and_in_cluster(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--mode",
            "dry_run",
            "--kubeconfig",
            str(kubeconfig),
            "--in-cluster",
        ],
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_run_refuses_dry_run_without_cluster_access(tmp_path: Path) -> None:
    """`--mode dry_run` or `--mode execute` requires --kubeconfig or --in-cluster."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    auth = _auth_yaml(
        tmp_path,
        mode_recommend_authorized=True,
        mode_dry_run_authorized=True,
    )

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--mode",
            "dry_run",
        ],
    )
    assert result.exit_code != 0
    assert "requires cluster access" in result.output


def test_run_refuses_execute_without_cluster_access(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--mode",
            "execute",
        ],
    )
    assert result.exit_code != 0
    assert "requires cluster access" in result.output


# ---------------------------- run: mode-escalation gates ----------------


def test_run_surfaces_mode_escalation_as_usage_error(tmp_path: Path) -> None:
    """Default Authorization() refuses dry_run; the CLI surfaces it as UsageError."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")
    # Auth doesn't opt into dry_run.
    auth = _auth_yaml(tmp_path, mode_recommend_authorized=True)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--mode",
            "dry_run",
            "--kubeconfig",
            str(kubeconfig),
        ],
    )
    assert result.exit_code != 0
    assert "mode_dry_run_authorized: true" in result.output


# ---------------------------- run: rollback window override -------------


def test_run_accepts_rollback_window_override(tmp_path: Path) -> None:
    """`--rollback-window-sec` overrides the auth.yaml value (still recommend mode)."""
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)
    auth = _auth_yaml(
        tmp_path,
        mode_recommend_authorized=True,
        rollback_window_sec=600,
    )

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--auth",
            str(auth),
            "--rollback-window-sec",
            "120",
        ],
    )
    assert result.exit_code == 0, result.output


def test_run_rejects_rollback_window_outside_range(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    findings = _empty_findings_json(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--findings",
            str(findings),
            "--rollback-window-sec",
            "30",
        ],
    )
    assert result.exit_code != 0
    # Click's IntRange formats the message as "30 is not in the range 60<=x<=1800".
    assert "60" in result.output


# ---------------------------- run: required-arg / file checks -----------


def test_run_missing_contract_exits_nonzero(tmp_path: Path) -> None:
    findings = _empty_findings_json(tmp_path)
    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(tmp_path / "no.yaml"), "--findings", str(findings)],
    )
    assert result.exit_code != 0


def test_run_missing_findings_exits_nonzero(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--findings", str(tmp_path / "no.json")],
    )
    assert result.exit_code != 0
