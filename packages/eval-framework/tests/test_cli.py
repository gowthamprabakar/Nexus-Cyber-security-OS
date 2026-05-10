"""Tests for the `eval-framework` CLI — run / compare / gate subcommands."""

from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from eval_framework.cli import cli
from eval_framework.runner import FakeRunner


@pytest.fixture
def cases_dir(tmp_path: Path) -> Path:
    """A fixture directory with two YAML cases the FakeRunner will pass by default."""
    d = tmp_path / "cases"
    d.mkdir()
    for case_id in ("001_a", "002_b"):
        (d / f"{case_id}.yaml").write_text(
            textwrap.dedent(
                f"""
                case_id: {case_id}
                description: smoke
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
    return d


@pytest.fixture
def fake_registered() -> object:
    """Patch the runner registry so the CLI resolves "fake" → FakeRunner()."""

    def _resolve(name: str) -> FakeRunner:
        if name == "fake":
            return FakeRunner(agent_name="fake")
        if name == "fake_failing":
            return FakeRunner(agent_name="fake_failing", default_passed=False)
        raise KeyError(f"no runner named {name!r}")

    with patch("eval_framework.cli._resolve_runner", side_effect=_resolve):
        yield


# ---------------------------- --help -------------------------------------


def test_cli_help_lists_subcommands() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "run" in result.output
    assert "compare" in result.output
    assert "gate" in result.output


# ---------------------------- run ----------------------------------------


def test_run_writes_suite_json(cases_dir: Path, tmp_path: Path, fake_registered: object) -> None:
    out = tmp_path / "suite.json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["run", "--runner", "fake", "--cases", str(cases_dir), "--output", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert "2/2 passed" in result.output
    assert out.exists()

    payload = json.loads(out.read_text())
    assert payload["runner"] == "fake"
    assert {c["case_id"] for c in payload["cases"]} == {"001_a", "002_b"}


def test_run_failing_suite_exits_zero_but_reports_failures(
    cases_dir: Path, tmp_path: Path, fake_registered: object
) -> None:
    """`run` reports failures but doesn't exit non-zero — that's `gate`'s job."""
    out = tmp_path / "suite.json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "run",
            "--runner",
            "fake_failing",
            "--cases",
            str(cases_dir),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    assert "0/2" in result.output


def test_run_unknown_runner_exits_nonzero(
    cases_dir: Path, tmp_path: Path, fake_registered: object
) -> None:
    out = tmp_path / "suite.json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "run",
            "--runner",
            "does_not_exist",
            "--cases",
            str(cases_dir),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code != 0
    assert "no runner named" in result.output.lower() or "does_not_exist" in result.output


# ---------------------------- compare ------------------------------------


def _write_suite(path: Path, suite_id: str, *, failing_ids: tuple[str, ...] = ()) -> None:
    """Synthesize a SuiteResult JSON payload directly."""
    cases = []
    for case_id in ("001", "002"):
        cases.append(
            {
                "case_id": case_id,
                "runner": "fake",
                "passed": case_id not in failing_ids,
                "failure_reason": None if case_id not in failing_ids else "boom",
                "actuals": {},
                "duration_sec": 0.1,
                "trace": {
                    "audit_log_path": None,
                    "llm_calls": [],
                    "tool_calls": [],
                    "output_writes": [],
                    "audit_chain_valid": None,
                },
            }
        )
    path.write_text(
        json.dumps(
            {
                "suite_id": suite_id,
                "runner": "fake",
                "started_at": "2026-05-10T00:00:00+00:00",
                "completed_at": "2026-05-10T00:00:01+00:00",
                "cases": cases,
                "provider_id": None,
                "model_pin": None,
                "metadata": {},
            }
        ),
        encoding="utf-8",
    )


def test_compare_identical_suites_reports_zero_drift(tmp_path: Path) -> None:
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    _write_suite(a, "A")
    _write_suite(b, "B")

    out = tmp_path / "report.md"
    runner = CliRunner()
    result = runner.invoke(cli, ["compare", str(a), str(b), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    content = out.read_text()
    assert "0 regression" in content


def test_compare_with_regression_surfaces_it(tmp_path: Path) -> None:
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    _write_suite(a, "A")
    _write_suite(b, "B", failing_ids=("002",))

    out = tmp_path / "report.md"
    runner = CliRunner()
    result = runner.invoke(cli, ["compare", str(a), str(b), "--output", str(out)])
    assert result.exit_code == 0
    content = out.read_text()
    assert "1 regression" in content
    assert "002" in content


# ---------------------------- gate ---------------------------------------


def _write_gate_yaml(path: Path, *, min_pass_rate: float = 1.0) -> None:
    path.write_text(
        textwrap.dedent(
            f"""
            min_pass_rate: {min_pass_rate}
            no_regressions_vs_baseline: true
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def test_gate_passing_suite_exits_zero(tmp_path: Path) -> None:
    suite = tmp_path / "suite.json"
    _write_suite(suite, "S")

    gate_cfg = tmp_path / "gate.yaml"
    _write_gate_yaml(gate_cfg, min_pass_rate=1.0)

    runner = CliRunner()
    result = runner.invoke(cli, ["gate", str(suite), "--config", str(gate_cfg)])
    assert result.exit_code == 0
    assert "passed" in result.output.lower()


def test_gate_failing_suite_exits_nonzero(tmp_path: Path) -> None:
    suite = tmp_path / "suite.json"
    _write_suite(suite, "S", failing_ids=("002",))

    gate_cfg = tmp_path / "gate.yaml"
    _write_gate_yaml(gate_cfg, min_pass_rate=1.0)

    runner = CliRunner()
    result = runner.invoke(cli, ["gate", str(suite), "--config", str(gate_cfg)])
    assert result.exit_code != 0
    assert "failed" in result.output.lower() or "pass_rate" in result.output


def test_gate_with_baseline(tmp_path: Path) -> None:
    """A baseline-aware gate catches a regression even when min_pass_rate is permissive."""
    baseline = tmp_path / "baseline.json"
    candidate = tmp_path / "candidate.json"
    _write_suite(baseline, "A")
    _write_suite(candidate, "B", failing_ids=("002",))

    gate_cfg = tmp_path / "gate.yaml"
    gate_cfg.write_text(
        textwrap.dedent(
            """
            min_pass_rate: 0.0
            no_regressions_vs_baseline: true
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "gate",
            str(candidate),
            "--config",
            str(gate_cfg),
            "--baseline",
            str(baseline),
        ],
    )
    assert result.exit_code != 0
    assert "regression" in result.output.lower()


def test_main_returns_int(fake_registered: object) -> None:
    """The `main()` entry-point used by [project.scripts] must return an int."""
    from eval_framework.cli import main

    # Use sys.argv shim because click's standalone_mode otherwise raises SystemExit.
    with (
        patch.object(sys, "argv", ["eval-framework", "--help"]),
        patch.dict(os.environ, {}, clear=False),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()
    assert exc_info.value.code == 0
