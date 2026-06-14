"""Tests — `supervisor.cli` (Task 13).

16 tests covering the 4 CLI subcommands via Click's CliRunner:

1.  ``supervisor --help`` lists 4 subcommands.
2.  ``supervisor --version`` prints package version.
3.  ``supervisor eval`` against the bundled cases exits 0 with
    15/15 passed.
4.  ``supervisor eval <bad-dir>`` exits non-zero.
5.  ``supervisor eval <empty-dir>`` exits 0 with "0/0 passed".
6.  ``supervisor heartbeat-once`` with no extra task drains a
    queued task + completes the tick.
7.  ``supervisor heartbeat-once --task-id ... --target-agent ...``
    injects + dispatches the operator-CLI task.
8.  ``supervisor heartbeat-once --task-id`` without any routing
    key flags exits non-zero.
9.  ``supervisor schedule --task-id ... --target-agent ...``
    enqueues the task to the JSON queue file.
10. ``supervisor schedule`` without any routing key flags exits
    non-zero.
11. ``supervisor schedule`` rejects missing --customer-id.
12. ``supervisor schedule`` rejects missing --task-id.
13. ``supervisor run --max-ticks 2 --tick-interval-seconds 0.01``
    completes 2 ticks + prints the digest.
14. ``supervisor run`` rejects missing --customer-id.
15. ``supervisor run`` rejects tick_interval_seconds <= 0 via Click.
16. ``supervisor heartbeat-once`` writes both the audit log and
    ``supervisor_report.md`` to --workspace-root.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from supervisor import __version__
from supervisor.cli import _resolve_continuous_source, main
from supervisor.continuous_source import ContinuousTriggerSource


@pytest.fixture
def cli() -> CliRunner:
    return CliRunner()


def test_help_lists_subcommands(cli: CliRunner) -> None:
    result = cli.invoke(main, ["--help"])
    assert result.exit_code == 0
    for sub in ("eval", "heartbeat-once", "schedule", "run"):
        assert sub in result.output


def test_version_prints_package_version(cli: CliRunner) -> None:
    result = cli.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


# ---------------------------------------------------------------------------
# eval
# ---------------------------------------------------------------------------


def test_eval_bundled_cases_pass(cli: CliRunner) -> None:
    result = cli.invoke(main, ["eval"])
    assert result.exit_code == 0, result.output
    assert "15/15 passed" in result.output


def test_eval_bad_dir_exits_non_zero(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(main, ["eval", str(tmp_path / "nope")])
    assert result.exit_code != 0


def test_eval_empty_dir_exits_0(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(main, ["eval", str(tmp_path)])
    assert result.exit_code == 0
    assert "0/0 passed" in result.output


# ---------------------------------------------------------------------------
# heartbeat-once
# ---------------------------------------------------------------------------


def test_heartbeat_once_drains_queued_task(cli: CliRunner, tmp_path: Path) -> None:
    # Enqueue a task first.
    result = cli.invoke(
        main,
        [
            "schedule",
            "--customer-id",
            "acme",
            "--task-id",
            "t1",
            "--target-agent",
            "cloud_posture",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output

    # Now run a heartbeat — it should drain + dispatch.
    result = cli.invoke(
        main,
        [
            "heartbeat-once",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "triggers=1" in result.output
    assert "delegations=1" in result.output


def test_heartbeat_once_injects_operator_cli_task(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        [
            "heartbeat-once",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--task-id",
            "t1",
            "--target-agent",
            "cloud_posture",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "triggers=1" in result.output


def test_heartbeat_once_task_id_without_keys_errors(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        [
            "heartbeat-once",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--task-id",
            "t1",
            # no --target-agent / --task-type / --delta-type
        ],
    )
    assert result.exit_code != 0


def test_heartbeat_once_writes_report_and_audit(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        [
            "heartbeat-once",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--task-id",
            "t1",
            "--target-agent",
            "cloud_posture",
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "supervisor_report.md").is_file()
    assert (tmp_path / "audit.jsonl").is_file()


# ---------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------


def test_schedule_enqueues_to_json_file(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        [
            "schedule",
            "--customer-id",
            "acme",
            "--task-id",
            "t1",
            "--target-agent",
            "cloud_posture",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    queue_file = tmp_path / ".supervisor" / "scheduled" / "acme.json"
    assert queue_file.is_file()
    payload = json.loads(queue_file.read_text(encoding="utf-8"))
    assert len(payload) == 1
    assert payload[0]["task_id"] == "t1"
    assert payload[0]["target_agent"] == "cloud_posture"


def test_schedule_without_routing_key_errors(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        [
            "schedule",
            "--customer-id",
            "acme",
            "--task-id",
            "t1",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code != 0


def test_schedule_rejects_missing_customer_id(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        ["schedule", "--task-id", "t1", "--target-agent", "cloud_posture"],
    )
    assert result.exit_code != 0


def test_schedule_rejects_missing_task_id(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        ["schedule", "--customer-id", "acme", "--target-agent", "cloud_posture"],
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_with_max_ticks_completes(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--tick-interval-seconds",
            "0.01",
            "--max-ticks",
            "2",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "ticks completed: 2" in result.output


def test_run_rejects_missing_customer_id(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        ["run", "--max-ticks", "1", "--workspace-root", str(tmp_path)],
    )
    assert result.exit_code != 0


def test_run_rejects_zero_tick_interval(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--tick-interval-seconds",
            "0.0",
            "--max-ticks",
            "1",
        ],
    )
    assert result.exit_code != 0


# ---------------------- Track D D-1: continuous-mode CLI wiring ----------


def test_resolve_continuous_source_off_by_default() -> None:
    """Default OFF → no continuous source (heartbeat-only preserved)."""
    src, decision = _resolve_continuous_source(continuous_mode=False, continuous_kill_switch=False)
    assert src is None
    assert decision["continuous_effective"] is False


def test_resolve_continuous_source_on_builds_trigger_source() -> None:
    """--continuous-mode → a wired (but inert) ContinuousTriggerSource."""
    src, decision = _resolve_continuous_source(continuous_mode=True, continuous_kill_switch=False)
    assert isinstance(src, ContinuousTriggerSource)
    assert decision["continuous_effective"] is True


def test_resolve_continuous_source_kill_switch_overrides() -> None:
    """Per-tenant kill-switch forces OFF even when continuous-mode is requested."""
    src, decision = _resolve_continuous_source(continuous_mode=True, continuous_kill_switch=True)
    assert src is None
    assert decision["continuous_effective"] is False
    assert decision["continuous_kill_switch"] is True


def test_run_default_reports_heartbeat_only(cli: CliRunner, tmp_path: Path) -> None:
    """`run` with no continuous flag echoes continuous_effective=false + completes."""
    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--tick-interval-seconds",
            "0.01",
            "--max-ticks",
            "1",
        ],
    )
    assert result.exit_code == 0, result.output
    assert '"continuous_effective":false' in result.output
    assert "ticks completed: 1" in result.output


def test_run_continuous_mode_wires_and_completes(cli: CliRunner, tmp_path: Path) -> None:
    """`run --continuous-mode` echoes continuous_effective=true + still completes."""
    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--tick-interval-seconds",
            "0.01",
            "--max-ticks",
            "1",
            "--continuous-mode",
        ],
    )
    assert result.exit_code == 0, result.output
    assert '"continuous_effective":true' in result.output
    assert "ticks completed: 1" in result.output


def test_run_kill_switch_overrides_continuous_mode(cli: CliRunner, tmp_path: Path) -> None:
    """`run --continuous-mode --continuous-kill-switch` → effective false (override)."""
    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--tick-interval-seconds",
            "0.01",
            "--max-ticks",
            "1",
            "--continuous-mode",
            "--continuous-kill-switch",
        ],
    )
    assert result.exit_code == 0, result.output
    assert '"continuous_effective":false' in result.output


def test_run_echoes_continuous_cadence_from_env(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Track D D-2: the resolved per-tenant cadence is surfaced in the decision
    record (inert — echoed, not registered with any driver)."""
    monkeypatch.setenv("NEXUS_CONTINUOUS_CADENCE", "weekly")
    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--tick-interval-seconds",
            "0.01",
            "--max-ticks",
            "1",
        ],
    )
    assert result.exit_code == 0, result.output
    assert '"continuous_cadence":"weekly"' in result.output


def test_run_continuous_cadence_null_by_default(cli: CliRunner, tmp_path: Path) -> None:
    """Default (no cadence configured) → continuous_cadence null."""
    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--workspace-root",
            str(tmp_path),
            "--tick-interval-seconds",
            "0.01",
            "--max-ticks",
            "1",
        ],
    )
    assert result.exit_code == 0, result.output
    assert '"continuous_cadence":null' in result.output
