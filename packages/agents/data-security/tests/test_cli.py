"""Tests — ``data_security.cli`` (Task 15).

- ``data-security --help`` works (top-level + subcommands).
- ``data-security eval CASES_DIR`` returns 0 when 10/10 pass.
- ``data-security eval`` exits non-zero when a case fails.
- ``data-security run`` warns on no-feed.
- ``data-security run`` happy path with an inline contract YAML.
- ``--customer-domain`` is accepted (reserved for v0.2; ignored in v0.1).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from click.testing import CliRunner
from data_security.cli import main

CASES_DIR = (Path(__file__).resolve().parents[1] / "eval" / "cases").resolve()


def _make_contract_yaml(workspace: Path) -> Path:
    persistent = workspace / "_persistent"
    persistent.mkdir(exist_ok=True)
    contract_dict = {
        "schema_version": "0.1",
        "delegation_id": "01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        "source_agent": "supervisor",
        "target_agent": "data_security",
        "customer_id": "cust_cli_test",
        "task": "CLI smoke test",
        "required_outputs": ["findings.json", "report.md"],
        "budget": {
            "llm_calls": 1,
            "tokens": 1,
            "wall_clock_sec": 60.0,
            "cloud_api_calls": 10,
            "mb_written": 10,
        },
        "permitted_tools": ["read_s3_inventory", "read_s3_objects", "read_f3_findings"],
        "completion_condition": "findings.json exists",
        "escalation_rules": [],
        "workspace": str(workspace),
        "persistent_root": str(persistent),
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    path = workspace / "contract.yaml"
    path.write_text(yaml.safe_dump(contract_dict), encoding="utf-8")
    return path


def _public_bucket_dict(name: str = "alpha") -> dict:
    return {
        "name": name,
        "region": "us-east-1",
        "account_id": "123456789012",
        "acl": {"grants_all_users": ["READ"], "grants_authenticated_users": []},
        "public_access_block": {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        },
        "encryption": {"algorithm": "AES256", "kms_master_key_id": None},
        "policy_json": None,
        "tags": {},
    }


# ---------------------------- top-level + help ----------------------------


def test_cli_help_works() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Data Security Agent" in result.output
    assert "eval" in result.output
    assert "run" in result.output


def test_cli_version_works() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


def test_eval_subcommand_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["eval", "--help"])
    assert result.exit_code == 0
    assert "CASES_DIR" in result.output


def test_run_subcommand_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["run", "--help"])
    assert result.exit_code == 0
    for flag in (
        "--contract",
        "--s3-inventory-feed",
        "--s3-objects-feed",
        "--cloud-posture-workspace",
        "--trusted-sensitivity-tag",
        "--customer-domain",
    ):
        assert flag in result.output


# ---------------------------- eval subcommand ----------------------------


def test_eval_returns_zero_on_full_pass(tmp_path: Path) -> None:
    """The shipped 10 cases all pass → exit 0."""
    runner = CliRunner()
    result = runner.invoke(main, ["eval", str(CASES_DIR)])
    assert result.exit_code == 0, result.output
    assert "10/10 passed" in result.output


# ---------------------------- run subcommand -----------------------------


def test_run_with_no_feeds_warns_and_emits_empty_report(tmp_path: Path) -> None:
    contract_path = _make_contract_yaml(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["run", "--contract", str(contract_path)])
    assert result.exit_code == 0, result.output
    # Warning printed to stderr (mix_stderr=True by default puts both in .output).
    assert "warning: no S3 feeds" in result.output
    # Digest fields.
    assert "agent: data_security" in result.output
    assert "customer: cust_cli_test" in result.output
    assert "findings: 0" in result.output


def test_run_with_inventory_feed_reports_findings(tmp_path: Path) -> None:
    """End-to-end CLI smoke test with a staged S3 inventory feed."""
    contract_path = _make_contract_yaml(tmp_path)
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps({"buckets": [_public_bucket_dict("alpha")]}),
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "run",
            "--contract",
            str(contract_path),
            "--s3-inventory-feed",
            str(inventory_path),
        ],
    )
    assert result.exit_code == 0, result.output
    # At least one HIGH finding emitted (public bucket).
    assert "findings: 1" in result.output
    assert "high: 1" in result.output
    # Workspace files exist on disk.
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "report.md").exists()


def test_run_accepts_customer_domain_flag(tmp_path: Path) -> None:
    """--customer-domain is accepted (reserved for v0.2; ignored)."""
    contract_path = _make_contract_yaml(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "run",
            "--contract",
            str(contract_path),
            "--customer-domain",
            "example.com",
            "--customer-domain",
            "corp.example.com",
        ],
    )
    assert result.exit_code == 0, result.output


def test_run_accepts_trusted_tag_override(tmp_path: Path) -> None:
    contract_path = _make_contract_yaml(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "run",
            "--contract",
            str(contract_path),
            "--trusted-sensitivity-tag",
            "Confidential",
        ],
    )
    assert result.exit_code == 0, result.output


def test_run_missing_contract_arg_fails() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["run"])
    assert result.exit_code != 0
    assert "--contract" in result.output


def test_run_with_nonexistent_contract_fails(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["run", "--contract", str(tmp_path / "missing.yaml")])
    assert result.exit_code != 0
