"""Tests — D.13 Synthesis CLI (Task 12)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from synthesis.cli import main

_BUNDLED_CASES = Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="synthesis",
        customer_id="cust_test",
        task="Synthesis run",
        required_outputs=["narrative.md", "executive_summary.md"],
        budget=BudgetSpec(
            llm_calls=20,
            tokens=50_000,
            wall_clock_sec=60.0,
            cloud_api_calls=1,
            mb_written=10,
        ),
        permitted_tools=["read_sibling_workspaces"],
        completion_condition="narrative.md AND executive_summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(contract.model_dump(mode="json")))
    return path


def _stub_provider(canned: list[str]) -> object:
    """Return a FakeLLMProvider preloaded with canned responses."""
    from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage

    return FakeLLMProvider(
        [
            LLMResponse(
                text=text,
                stop_reason="end_turn",
                usage=TokenUsage(input_tokens=100, output_tokens=50),
                model_pin="claude-haiku-4-5-20251001",
            )
            for text in canned
        ]
    )


def _clean_canned() -> list[str]:
    return [
        json.dumps(
            {
                "overall_narrative_intent": "Cover the run.",
                "sections": [{"heading": "Section 1", "intent": "x", "cited_finding_ids": []}],
            }
        ),
        "Section 1 body.",
        json.dumps(
            {
                "paragraph": "Clean run summary.",
                "key_metrics": {
                    "total_findings": 0,
                    "critical": 0,
                    "high": 0,
                    "top_failing_control": "",
                },
            }
        ),
    ]


# ---------------------------------------------------------------------------
# --help / --version
# ---------------------------------------------------------------------------


def test_cli_help_lists_subcommands() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "eval" in result.output
    assert "run" in result.output


def test_cli_version_flag_prints_version() -> None:
    from synthesis import __version__

    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


# ---------------------------------------------------------------------------
# synthesis eval
# ---------------------------------------------------------------------------


def test_eval_command_with_default_cases_dir_passes() -> None:
    """No CASES_DIR argument -> uses the bundled suite (10 cases)."""
    result = CliRunner().invoke(main, ["eval"])
    assert result.exit_code == 0, result.output
    assert "10/10 passed" in result.output


def test_eval_command_with_explicit_cases_dir_passes() -> None:
    result = CliRunner().invoke(main, ["eval", str(_BUNDLED_CASES)])
    assert result.exit_code == 0, result.output
    assert "passed" in result.output


def test_eval_command_missing_dir_exits_nonzero(tmp_path: Path) -> None:
    """Click exits 2 on a non-existent directory at argument parse time."""
    result = CliRunner().invoke(main, ["eval", str(tmp_path / "missing")])
    assert result.exit_code != 0


def test_eval_command_empty_dir_reports_zero_total(tmp_path: Path) -> None:
    """Empty cases dir -> 0/0 passed, exit 0 (nothing failed)."""
    empty = tmp_path / "empty_cases"
    empty.mkdir()
    result = CliRunner().invoke(main, ["eval", str(empty)])
    assert result.exit_code == 0
    assert "0/0 passed" in result.output


# ---------------------------------------------------------------------------
# synthesis run
# ---------------------------------------------------------------------------


def test_run_command_requires_contract_path() -> None:
    result = CliRunner().invoke(main, ["run"])
    assert result.exit_code != 0
    assert "--contract" in result.output


def test_run_command_errors_without_llm_env_vars(tmp_path: Path) -> None:
    """No NEXUS_LLM_MODEL_PIN -> clear error, exit 2."""
    contract = _contract_yaml(tmp_path)
    runner = CliRunner()
    # Clean env to ensure NEXUS_LLM_MODEL_PIN absent.
    result = runner.invoke(
        main,
        ["run", "--contract", str(contract)],
        env={"NEXUS_LLM_PROVIDER": "anthropic"},
    )
    assert result.exit_code == 2
    assert "LLM configuration missing" in result.output


def test_run_command_warns_when_no_workspaces_provided(tmp_path: Path) -> None:
    """All 3 workspace flags omitted -> warning printed to stderr."""
    contract = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    with patch("synthesis.cli.make_provider", return_value=provider):
        result = CliRunner().invoke(
            main,
            ["run", "--contract", str(contract)],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert result.exit_code == 0, result.output
    assert "no --investigation-workspace" in result.output or "warning" in result.output


def test_run_command_emits_one_line_digest(tmp_path: Path) -> None:
    """Successful run prints `synthesis: N sections | M cited | K Q6 retries`."""
    contract = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    with patch("synthesis.cli.make_provider", return_value=provider):
        result = CliRunner().invoke(
            main,
            ["run", "--contract", str(contract)],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert result.exit_code == 0, result.output
    assert "synthesis:" in result.output
    assert "sections" in result.output
    assert "cited findings" in result.output
    assert "Q6 retries" in result.output


def test_run_command_prints_customer_and_run_id(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    with patch("synthesis.cli.make_provider", return_value=provider):
        result = CliRunner().invoke(
            main,
            ["run", "--contract", str(contract)],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert "cust_test" in result.output
    assert "01J7M3X9Z1K8RPVQNH2T8DBHFZ" in result.output


def test_run_command_model_pin_flag_overrides_default(tmp_path: Path) -> None:
    """--model-pin TEXT passes through to agent.run."""
    contract = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    captured_model_pin: dict[str, str] = {}

    async def fake_run(*args: object, **kwargs: object) -> object:
        captured_model_pin["v"] = str(kwargs.get("model_pin", ""))
        from synthesis.agent import run as real_run

        return await real_run(*args, **kwargs)  # type: ignore[arg-type]

    with (
        patch("synthesis.cli.make_provider", return_value=provider),
        patch("synthesis.cli.agent_run", side_effect=fake_run),
    ):
        result = CliRunner().invoke(
            main,
            [
                "run",
                "--contract",
                str(contract),
                "--model-pin",
                "custom-model-pin-x",
            ],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "ignored"},
        )
    assert result.exit_code == 0, result.output
    assert captured_model_pin.get("v") == "custom-model-pin-x"


def test_run_command_propagates_workspace_flags(tmp_path: Path) -> None:
    """All 3 workspace flags pass through to agent.run."""
    contract = _contract_yaml(tmp_path)
    cp_ws = tmp_path / "cspm"
    cp_ws.mkdir()
    (cp_ws / "findings.json").write_text(json.dumps({"findings": []}))

    provider = _stub_provider(_clean_canned())
    captured: dict[str, object] = {}

    async def fake_run(*args: object, **kwargs: object) -> object:
        captured["cloud_posture_workspace"] = kwargs.get("cloud_posture_workspace")
        from synthesis.agent import run as real_run

        return await real_run(*args, **kwargs)  # type: ignore[arg-type]

    with (
        patch("synthesis.cli.make_provider", return_value=provider),
        patch("synthesis.cli.agent_run", side_effect=fake_run),
    ):
        result = CliRunner().invoke(
            main,
            [
                "run",
                "--contract",
                str(contract),
                "--cloud-posture-workspace",
                str(cp_ws),
            ],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert result.exit_code == 0, result.output
    assert str(captured["cloud_posture_workspace"]) == str(cp_ws)


def test_run_command_writes_markdown_to_workspace(tmp_path: Path) -> None:
    contract_path = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    with patch("synthesis.cli.make_provider", return_value=provider):
        result = CliRunner().invoke(
            main,
            ["run", "--contract", str(contract_path)],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert result.exit_code == 0, result.output
    narrative = tmp_path / "ws" / "narrative.md"
    summary = tmp_path / "ws" / "executive_summary.md"
    assert narrative.exists()
    assert summary.exists()
