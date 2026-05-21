"""Tests — D.12 Curiosity CLI (Task 13)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from curiosity.cli import main

_BUNDLED_CASES = Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="curiosity",
        customer_id="cust_test",
        task="Curiosity run",
        required_outputs=["hypotheses.md", "probe_directives.json"],
        budget=BudgetSpec(
            llm_calls=10,
            tokens=50_000,
            wall_clock_sec=60.0,
            cloud_api_calls=1,
            mb_written=10,
        ),
        permitted_tools=["read_sibling_state"],
        completion_condition="hypotheses.md AND probe_directives.json exist",
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
    """One LLM response — but the v0.1 CLI run with semantic_store=None
    short-circuits before the LLM call (no gaps detected). The FakeLLM
    is here just to satisfy the agent's `llm_provider` contract."""
    return [
        json.dumps(
            {
                "hypotheses": [
                    {
                        "statement": "Region under-scanned.",
                        "rationale": "x" * 200,
                        "probe_directive": {
                            "target_agent": "data_security",
                            "target_resource_arn": "arn:x",
                            "action": "scan",
                            "rationale_ref": "",
                        },
                        "cited_gap": {
                            "region": "us-east-1",
                            "asset_count": 30,
                            "days_since_last_finding": 60,
                            "severity_hint": "medium",
                        },
                    }
                ]
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
    from curiosity import __version__

    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


# ---------------------------------------------------------------------------
# curiosity eval
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
# curiosity run
# ---------------------------------------------------------------------------


def test_run_command_requires_contract_path() -> None:
    result = CliRunner().invoke(main, ["run"])
    assert result.exit_code != 0
    assert "--contract" in result.output


def test_run_command_errors_without_llm_env_vars(tmp_path: Path) -> None:
    """No NEXUS_LLM_MODEL_PIN -> clear error, exit 2."""
    contract = _contract_yaml(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["run", "--contract", str(contract)],
        env={"NEXUS_LLM_PROVIDER": "anthropic"},
    )
    assert result.exit_code == 2
    assert "LLM configuration missing" in result.output


def test_run_command_emits_one_line_digest(tmp_path: Path) -> None:
    """Successful run prints the curiosity digest line."""
    contract = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    with patch("curiosity.cli.make_provider", return_value=provider):
        result = CliRunner().invoke(
            main,
            ["run", "--contract", str(contract)],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert result.exit_code == 0, result.output
    assert "curiosity:" in result.output
    assert "hypotheses" in result.output
    assert "gaps addressed" in result.output
    assert "Q6 retries" in result.output


def test_run_command_prints_customer_and_run_id(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    with patch("curiosity.cli.make_provider", return_value=provider):
        result = CliRunner().invoke(
            main,
            ["run", "--contract", str(contract)],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert "cust_test" in result.output
    assert "01J7M3X9Z1K8RPVQNH2T8DBHFZ" in result.output


def test_run_command_semantic_store_dsn_warns(tmp_path: Path) -> None:
    """v0.1 ignores --semantic-store-dsn but logs a warning."""
    contract = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    with patch("curiosity.cli.make_provider", return_value=provider):
        result = CliRunner().invoke(
            main,
            [
                "run",
                "--contract",
                str(contract),
                "--semantic-store-dsn",
                "postgres://localhost/curiosity",
            ],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert result.exit_code == 0, result.output
    assert "semantic-store-dsn" in result.output
    assert "v0.2" in result.output or "single-tenant" in result.output


def test_run_command_nats_url_warns(tmp_path: Path) -> None:
    """v0.1 ignores --nats-url but logs a warning."""
    contract = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    with patch("curiosity.cli.make_provider", return_value=provider):
        result = CliRunner().invoke(
            main,
            [
                "run",
                "--contract",
                str(contract),
                "--nats-url",
                "nats://localhost:4222",
            ],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert result.exit_code == 0, result.output
    assert "nats-url" in result.output


def test_run_command_model_pin_flag_overrides_default(tmp_path: Path) -> None:
    """--model-pin TEXT passes through to agent.run."""
    contract = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    captured_model_pin: dict[str, str] = {}

    async def fake_run(*args: object, **kwargs: object) -> object:
        captured_model_pin["v"] = str(kwargs.get("model_pin", ""))
        from curiosity.agent import run as real_run

        return await real_run(*args, **kwargs)  # type: ignore[arg-type]

    with (
        patch("curiosity.cli.make_provider", return_value=provider),
        patch("curiosity.cli.agent_run", side_effect=fake_run),
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


def test_run_command_writes_markdown_and_json_to_workspace(tmp_path: Path) -> None:
    contract_path = _contract_yaml(tmp_path)
    provider = _stub_provider(_clean_canned())
    with patch("curiosity.cli.make_provider", return_value=provider):
        result = CliRunner().invoke(
            main,
            ["run", "--contract", str(contract_path)],
            env={"NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_MODEL_PIN": "claude-haiku-4-5"},
        )
    assert result.exit_code == 0, result.output
    md = tmp_path / "ws" / "hypotheses.md"
    js = tmp_path / "ws" / "probe_directives.json"
    assert md.exists()
    assert js.exists()
