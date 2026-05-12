"""Tests for the `investigation-agent` CLI (D.7 Task 15).

Production contract:

- Three subcommands: `eval`, `run`, `triage`.
- `eval CASES_DIR` runs the suite; exits 0 on full pass, 1 on failure.
- `run --contract path.yaml [--sibling-workspace ...]` drives the
  agent and writes the four artifacts to the contract workspace.
- `triage --contract path.yaml` is the Mode-A fast-path: same pipeline
  as `run`, but operator-facing prints (no LLM-required) — emits a
  shortened summary to stdout.
"""

from __future__ import annotations

import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from investigation.cli import main

_TENANT_A = "01HV0T0000000000000000TENA"


@pytest.fixture
def shipped_cases_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="investigation",
        customer_id=_TENANT_A,
        task="Investigate",
        required_outputs=[
            "incident_report.json",
            "timeline.json",
            "hypotheses.md",
            "containment_plan.yaml",
        ],
        budget=BudgetSpec(
            llm_calls=30,
            tokens=60000,
            wall_clock_sec=600.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=[
            "audit_trail_query",
            "memory_neighbors_walk",
            "find_related_findings",
            "extract_iocs",
            "map_to_mitre",
            "reconstruct_timeline",
            "synthesize_hypotheses",
        ],
        completion_condition="incident_report.json exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(contract.model_dump(mode="json")))
    return path


# ---------------------------- --help / --version ----------------------


def test_cli_help_lists_three_subcommands() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "eval" in result.output
    assert "run" in result.output
    assert "triage" in result.output


def test_cli_version_flag() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


# ---------------------------- eval ------------------------------------


def test_eval_with_shipped_cases_passes_10_of_10(shipped_cases_dir: Path) -> None:
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
              audit_events: []
              sibling_findings: []
              llm_response: null
            expected:
              hypotheses_count: 999
            """
        )
    )
    result = CliRunner().invoke(main, ["eval", str(cases_dir)])
    assert result.exit_code == 1
    assert "0/1 passed" in result.output
    assert "FAIL 001_bogus" in result.output


# ---------------------------- run -------------------------------------


def test_run_writes_four_artifacts(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["run", "--contract", str(_contract_yaml(tmp_path))])
    assert result.exit_code == 0, result.output
    ws = tmp_path / "ws"
    assert (ws / "incident_report.json").is_file()
    assert (ws / "timeline.json").is_file()
    assert (ws / "hypotheses.md").is_file()
    assert (ws / "containment_plan.yaml").is_file()


def test_run_prints_digest_to_stdout(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["run", "--contract", str(_contract_yaml(tmp_path))])
    assert "agent: investigation" in result.output
    assert "hypotheses: 0" in result.output
    assert "timeline events: 0" in result.output


# ---------------------------- triage ----------------------------------


def test_triage_emits_concise_summary(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["triage", "--contract", str(_contract_yaml(tmp_path))])
    assert result.exit_code == 0, result.output
    # Triage prints a one-screen summary — confidence + hypothesis count.
    assert "Triage summary" in result.output
    assert "confidence" in result.output.lower()
