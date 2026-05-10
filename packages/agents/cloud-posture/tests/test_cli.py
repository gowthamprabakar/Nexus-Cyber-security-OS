"""Tests for the cloud-posture CLI."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from cloud_posture.cli import main

# ---------------------- top-level ------------------------------------------


def test_main_help_lists_subcommands() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "eval" in result.output
    assert "run" in result.output


def test_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    # Click prints something like "main, version 0.1.0"
    assert "0.1.0" in result.output or "main" in result.output


# ---------------------- eval subcommand ------------------------------------


def _write_passing_case(eval_dir: Path, name: str = "001_x.yaml") -> None:
    eval_dir.mkdir(parents=True, exist_ok=True)
    (eval_dir / name).write_text(
        """
case_id: 001_x
description: empty
fixture:
  prowler_findings: []
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 0
  has_severity:
    critical: 0
    high: 0
"""
    )


def _write_failing_case(eval_dir: Path) -> None:
    """Bob without MFA but expected finding_count=0 → mismatch."""
    eval_dir.mkdir(parents=True, exist_ok=True)
    (eval_dir / "002_fail.yaml").write_text(
        """
case_id: 002_fail
description: bob without mfa expected zero
fixture:
  prowler_findings: []
  iam_users_without_mfa: [bob]
  iam_admin_policies: []
expected:
  finding_count: 0
  has_severity:
    high: 0
"""
    )


def test_eval_passes_on_clean_case(tmp_path: Path) -> None:
    eval_dir = tmp_path / "cases"
    _write_passing_case(eval_dir)

    runner = CliRunner()
    result = runner.invoke(main, ["eval", str(eval_dir)])
    assert result.exit_code == 0, result.output
    assert "1/1 passed" in result.output


def test_eval_exits_nonzero_on_failure(tmp_path: Path) -> None:
    eval_dir = tmp_path / "cases"
    _write_passing_case(eval_dir)
    _write_failing_case(eval_dir)

    runner = CliRunner()
    result = runner.invoke(main, ["eval", str(eval_dir)])
    assert result.exit_code != 0, result.output
    assert "1/2 passed" in result.output
    assert "FAIL 002_fail" in result.output
    assert "finding_count" in result.output


def test_eval_rejects_missing_directory(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["eval", str(tmp_path / "does-not-exist")])
    assert result.exit_code != 0


def test_eval_handles_empty_directory(tmp_path: Path) -> None:
    eval_dir = tmp_path / "empty"
    eval_dir.mkdir()
    runner = CliRunner()
    result = runner.invoke(main, ["eval", str(eval_dir)])
    assert result.exit_code == 0
    assert "0/0 passed" in result.output


def test_eval_runs_all_shipped_cases() -> None:
    """End-to-end CLI smoke against the real shipped eval suite."""
    cases_dir = Path(__file__).resolve().parents[1] / "eval" / "cases"
    if not cases_dir.is_dir():
        return  # shipped suite not yet present (build order)

    runner = CliRunner()
    result = runner.invoke(main, ["eval", str(cases_dir)])
    assert result.exit_code == 0, result.output
    assert "10/10 passed" in result.output
