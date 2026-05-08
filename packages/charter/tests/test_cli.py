"""Tests for the charter CLI."""

from pathlib import Path

from charter.audit import AuditLog
from charter.cli import main
from click.testing import CliRunner

FIXTURES = Path(__file__).parent / "fixtures"


def test_validate_valid_contract() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["validate", str(FIXTURES / "valid_contract.yaml")])
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


def test_validate_invalid_contract() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["validate", str(FIXTURES / "invalid_contract.yaml")])
    assert result.exit_code != 0


def test_audit_verify_clean_log(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(path=log_path, agent="x", run_id="r")
    log.append(action="a", payload={})
    log.append(action="b", payload={})

    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify", str(log_path)])
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


def test_audit_verify_missing_file(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify", str(tmp_path / "nope.jsonl")])
    assert result.exit_code != 0
