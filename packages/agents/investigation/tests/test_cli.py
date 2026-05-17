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


# ---------------------------- --publish-events-to-bus flag (F.7 v0.2 Task 2) ----------------------------

# v0.2 Task 2 wires `--publish-events-to-bus` and `NEXUS_FABRIC_PUBLISH=1`
# from the CLI through to agent.run()'s `publish_events_to_bus` kwarg.
# No publish behaviour is added in v0.2 Task 2 — Task 3 lands the bus_emit
# module + the agent-driver branching. These tests prove the wire-through
# is correct + the off-by-default + env-fallback + CLI-wins-over-env
# precedence per the plan's Q3.


def test_resolve_publish_flag_default_off_when_neither_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from investigation.cli import _resolve_publish_flag

    monkeypatch.delenv("NEXUS_FABRIC_PUBLISH", raising=False)
    assert _resolve_publish_flag(None) is False


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "True", "yes", "YES", "Yes"])
def test_resolve_publish_flag_env_truthy_values_yield_true(
    monkeypatch: pytest.MonkeyPatch, truthy: str
) -> None:
    from investigation.cli import _resolve_publish_flag

    monkeypatch.setenv("NEXUS_FABRIC_PUBLISH", truthy)
    assert _resolve_publish_flag(None) is True


@pytest.mark.parametrize("falsy", ["0", "false", "FALSE", "no", "NO", "", "anything-else"])
def test_resolve_publish_flag_env_falsy_values_yield_false(
    monkeypatch: pytest.MonkeyPatch, falsy: str
) -> None:
    from investigation.cli import _resolve_publish_flag

    monkeypatch.setenv("NEXUS_FABRIC_PUBLISH", falsy)
    assert _resolve_publish_flag(None) is False


def test_resolve_publish_flag_cli_true_overrides_env_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI explicit True wins even when env says false."""
    from investigation.cli import _resolve_publish_flag

    monkeypatch.setenv("NEXUS_FABRIC_PUBLISH", "0")
    assert _resolve_publish_flag(True) is True


def test_resolve_publish_flag_cli_false_overrides_env_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI explicit False (--no-publish-events-to-bus) wins even when env says true.

    Load-bearing for the rollback path: an operator who sets the env var
    globally can still disable the flag for a specific invocation by
    passing --no-publish-events-to-bus.
    """
    from investigation.cli import _resolve_publish_flag

    monkeypatch.setenv("NEXUS_FABRIC_PUBLISH", "1")
    assert _resolve_publish_flag(False) is False


def test_run_flag_off_by_default_when_no_cli_flag_and_no_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Default behaviour is preserved: no CLI flag + no env → False reaches agent.run()."""
    import investigation.cli as cli_mod

    monkeypatch.delenv("NEXUS_FABRIC_PUBLISH", raising=False)
    captured: dict[str, object] = {}

    async def fake_agent_run(*args: object, **kwargs: object) -> object:
        captured["publish_events_to_bus"] = kwargs.get("publish_events_to_bus")
        # Return a minimal IncidentReport so the print stage doesn't crash.
        from datetime import UTC, datetime

        from investigation.schemas import IncidentReport, Timeline

        return IncidentReport(
            incident_id="01J7M3X9Z1K8RPVQNH2T8DBHF0",
            tenant_id=_TENANT_A,
            correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            timeline=Timeline(events=()),
            hypotheses=(),
            iocs=(),
            mitre_techniques=(),
            containment_summary="",
            confidence=0.0,
            emitted_at=datetime.now(UTC),
        )

    monkeypatch.setattr(cli_mod, "agent_run", fake_agent_run)

    result = CliRunner().invoke(main, ["run", "--contract", str(_contract_yaml(tmp_path))])
    assert result.exit_code == 0, result.output
    assert captured["publish_events_to_bus"] is False


def test_run_flag_on_via_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import investigation.cli as cli_mod

    monkeypatch.delenv("NEXUS_FABRIC_PUBLISH", raising=False)
    captured: dict[str, object] = {}

    async def fake_agent_run(*args: object, **kwargs: object) -> object:
        captured["publish_events_to_bus"] = kwargs.get("publish_events_to_bus")
        from datetime import UTC, datetime

        from investigation.schemas import IncidentReport, Timeline

        return IncidentReport(
            incident_id="01J7M3X9Z1K8RPVQNH2T8DBHF0",
            tenant_id=_TENANT_A,
            correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            timeline=Timeline(events=()),
            hypotheses=(),
            iocs=(),
            mitre_techniques=(),
            containment_summary="",
            confidence=0.0,
            emitted_at=datetime.now(UTC),
        )

    monkeypatch.setattr(cli_mod, "agent_run", fake_agent_run)

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(_contract_yaml(tmp_path)), "--publish-events-to-bus"],
    )
    assert result.exit_code == 0, result.output
    assert captured["publish_events_to_bus"] is True


def test_run_flag_on_via_env_var(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Env var alone (no CLI flag) flips the flag on."""
    import investigation.cli as cli_mod

    monkeypatch.setenv("NEXUS_FABRIC_PUBLISH", "1")
    captured: dict[str, object] = {}

    async def fake_agent_run(*args: object, **kwargs: object) -> object:
        captured["publish_events_to_bus"] = kwargs.get("publish_events_to_bus")
        from datetime import UTC, datetime

        from investigation.schemas import IncidentReport, Timeline

        return IncidentReport(
            incident_id="01J7M3X9Z1K8RPVQNH2T8DBHF0",
            tenant_id=_TENANT_A,
            correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            timeline=Timeline(events=()),
            hypotheses=(),
            iocs=(),
            mitre_techniques=(),
            containment_summary="",
            confidence=0.0,
            emitted_at=datetime.now(UTC),
        )

    monkeypatch.setattr(cli_mod, "agent_run", fake_agent_run)

    result = CliRunner().invoke(main, ["run", "--contract", str(_contract_yaml(tmp_path))])
    assert result.exit_code == 0, result.output
    assert captured["publish_events_to_bus"] is True


def test_run_cli_no_flag_overrides_env_true(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CLI --no-publish-events-to-bus disables the bus publish even when env says enable.

    End-to-end version of test_resolve_publish_flag_cli_false_overrides_env_true.
    """
    import investigation.cli as cli_mod

    monkeypatch.setenv("NEXUS_FABRIC_PUBLISH", "1")
    captured: dict[str, object] = {}

    async def fake_agent_run(*args: object, **kwargs: object) -> object:
        captured["publish_events_to_bus"] = kwargs.get("publish_events_to_bus")
        from datetime import UTC, datetime

        from investigation.schemas import IncidentReport, Timeline

        return IncidentReport(
            incident_id="01J7M3X9Z1K8RPVQNH2T8DBHF0",
            tenant_id=_TENANT_A,
            correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            timeline=Timeline(events=()),
            hypotheses=(),
            iocs=(),
            mitre_techniques=(),
            containment_summary="",
            confidence=0.0,
            emitted_at=datetime.now(UTC),
        )

    monkeypatch.setattr(cli_mod, "agent_run", fake_agent_run)

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(_contract_yaml(tmp_path)), "--no-publish-events-to-bus"],
    )
    assert result.exit_code == 0, result.output
    assert captured["publish_events_to_bus"] is False


def test_triage_flag_off_by_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import investigation.cli as cli_mod

    monkeypatch.delenv("NEXUS_FABRIC_PUBLISH", raising=False)
    captured: dict[str, object] = {}

    async def fake_agent_run(*args: object, **kwargs: object) -> object:
        captured["publish_events_to_bus"] = kwargs.get("publish_events_to_bus")
        from datetime import UTC, datetime

        from investigation.schemas import IncidentReport, Timeline

        return IncidentReport(
            incident_id="01J7M3X9Z1K8RPVQNH2T8DBHF0",
            tenant_id=_TENANT_A,
            correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            timeline=Timeline(events=()),
            hypotheses=(),
            iocs=(),
            mitre_techniques=(),
            containment_summary="",
            confidence=0.0,
            emitted_at=datetime.now(UTC),
        )

    monkeypatch.setattr(cli_mod, "agent_run", fake_agent_run)

    result = CliRunner().invoke(main, ["triage", "--contract", str(_contract_yaml(tmp_path))])
    assert result.exit_code == 0, result.output
    assert captured["publish_events_to_bus"] is False


def test_triage_flag_on_via_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import investigation.cli as cli_mod

    monkeypatch.delenv("NEXUS_FABRIC_PUBLISH", raising=False)
    captured: dict[str, object] = {}

    async def fake_agent_run(*args: object, **kwargs: object) -> object:
        captured["publish_events_to_bus"] = kwargs.get("publish_events_to_bus")
        from datetime import UTC, datetime

        from investigation.schemas import IncidentReport, Timeline

        return IncidentReport(
            incident_id="01J7M3X9Z1K8RPVQNH2T8DBHF0",
            tenant_id=_TENANT_A,
            correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            timeline=Timeline(events=()),
            hypotheses=(),
            iocs=(),
            mitre_techniques=(),
            containment_summary="",
            confidence=0.0,
            emitted_at=datetime.now(UTC),
        )

    monkeypatch.setattr(cli_mod, "agent_run", fake_agent_run)

    result = CliRunner().invoke(
        main,
        ["triage", "--contract", str(_contract_yaml(tmp_path)), "--publish-events-to-bus"],
    )
    assert result.exit_code == 0, result.output
    assert captured["publish_events_to_bus"] is True


def test_run_help_describes_publish_events_flag() -> None:
    result = CliRunner().invoke(main, ["run", "--help"])
    assert result.exit_code == 0
    assert "--publish-events-to-bus" in result.output
    assert "--no-publish-events-to-bus" in result.output
    assert "NEXUS_FABRIC_PUBLISH" in result.output


def test_triage_help_describes_publish_events_flag() -> None:
    result = CliRunner().invoke(main, ["triage", "--help"])
    assert result.exit_code == 0
    assert "--publish-events-to-bus" in result.output
    assert "--no-publish-events-to-bus" in result.output


def test_agent_run_accepts_publish_events_to_bus_kwarg() -> None:
    """The kwarg flows all the way to agent.run() and is accepted without
    error. v0.2 Task 2 does NOT yet branch on the kwarg — Task 3 does.
    This test pins the signature so a future refactor cannot remove the
    parameter without breaking Task 3's contract."""
    import inspect

    from investigation.agent import run as agent_run_fn

    sig = inspect.signature(agent_run_fn)
    assert "publish_events_to_bus" in sig.parameters
    assert sig.parameters["publish_events_to_bus"].default is False
