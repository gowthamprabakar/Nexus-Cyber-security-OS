"""Tests for the `audit-agent` CLI (F.6 Task 15).

Production contract:

- Three subcommands: `eval`, `run`, `query`.
- `eval CASES_DIR` runs the eval suite via the registered runner;
  exits 0 on full pass, 1 on any failure (same shape as D.3).
- `run` is the agent driver-facing path — accepts a contract YAML,
  optional jsonl sources, optional --memory-db, filter axes, and
  writes report.md + events.json to the contract's workspace.
- `query` is the operator-facing read path — emits markdown / csv /
  json. **Chain-break exit code is 2** so a cron job's downstream
  pipeline can distinguish "tooling failure (1)" from "tamper
  detected (2)" without parsing stderr.
- Always-on policy: a non-wall-clock budget overrun does not raise
  out of the CLI. (Exercised via the agent driver in test_agent.py;
  the CLI just trusts the driver.)
"""

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from audit.cli import main
from charter.audit import GENESIS_HASH, _hash_entry
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner

_TENANT_A = "01HV0T0000000000000000TENA"


@pytest.fixture
def shipped_cases_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "eval" / "cases"


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="audit",
        customer_id=_TENANT_A,
        task="Audit run",
        required_outputs=["report.md", "events.json"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["audit_jsonl_read", "episode_audit_read"],
        completion_condition="report.md exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(contract.model_dump(mode="json")))
    return path


def _write_chain(path: Path, *, n: int = 3) -> None:
    base = datetime(2026, 5, 1, tzinfo=UTC)
    previous = GENESIS_HASH
    lines: list[str] = []
    for i in range(n):
        emitted = (base + timedelta(seconds=i)).isoformat().replace("+00:00", "Z")
        payload = {"i": i}
        entry_hash = _hash_entry(
            timestamp=emitted,
            agent="cloud_posture",
            run_id=f"corr-{i:03d}",
            action="episode_appended",
            payload=payload,
            previous_hash=previous,
        )
        lines.append(
            json.dumps(
                {
                    "timestamp": emitted,
                    "agent": "cloud_posture",
                    "run_id": f"corr-{i:03d}",
                    "action": "episode_appended",
                    "payload": payload,
                    "previous_hash": previous,
                    "entry_hash": entry_hash,
                }
            )
        )
        previous = entry_hash
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------- --help / --version ----------------------


def test_cli_help_lists_three_subcommands() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "eval" in result.output
    assert "run" in result.output
    assert "query" in result.output


def test_cli_version_flag() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


# ---------------------------- eval ------------------------------------


def test_eval_with_shipped_cases_passes_10_of_10(shipped_cases_dir: Path) -> None:
    """The shipped 10 YAML cases all pass — same gate as test_eval_runner.py."""
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
              jsonl_events: []
              memory_events: []
              tampered_jsonl_index: null
              query:
                since: null
                until: null
                action: null
                agent_id: null
                correlation_id: null
            expected:
              total: 99
            """
        )
    )
    result = CliRunner().invoke(main, ["eval", str(cases_dir)])
    assert result.exit_code == 1
    assert "0/1 passed" in result.output
    assert "FAIL 001_bogus" in result.output


# ---------------------------- run -------------------------------------


def test_run_subcommand_writes_artifacts(tmp_path: Path) -> None:
    feed = tmp_path / "audit.jsonl"
    _write_chain(feed, n=3)

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(_contract_yaml(tmp_path)), "--source", str(feed)],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "ws" / "report.md").is_file()
    assert (tmp_path / "ws" / "events.json").is_file()
    assert "total: 3" in result.output


def test_run_without_sources_emits_empty_report(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["run", "--contract", str(_contract_yaml(tmp_path))])
    assert result.exit_code == 0, result.output
    assert "total: 0" in result.output


# ---------------------------- query -----------------------------------


def test_query_subcommand_emits_markdown_by_default(tmp_path: Path) -> None:
    feed = tmp_path / "audit.jsonl"
    _write_chain(feed, n=2)

    result = CliRunner().invoke(
        main,
        [
            "query",
            "--tenant",
            _TENANT_A,
            "--source",
            str(feed),
            "--workspace",
            str(tmp_path / "qws"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "# Audit summary" in result.output


def test_query_subcommand_emits_json_with_flag(tmp_path: Path) -> None:
    feed = tmp_path / "audit.jsonl"
    _write_chain(feed, n=2)

    result = CliRunner().invoke(
        main,
        [
            "query",
            "--tenant",
            _TENANT_A,
            "--source",
            str(feed),
            "--workspace",
            str(tmp_path / "qws"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["total"] == 2


def test_query_subcommand_emits_csv_with_flag(tmp_path: Path) -> None:
    feed = tmp_path / "audit.jsonl"
    _write_chain(feed, n=2)

    result = CliRunner().invoke(
        main,
        [
            "query",
            "--tenant",
            _TENANT_A,
            "--source",
            str(feed),
            "--workspace",
            str(tmp_path / "qws"),
            "--format",
            "csv",
        ],
    )
    assert result.exit_code == 0, result.output
    # CSV header line.
    assert result.output.splitlines()[0].startswith("emitted_at,")
    # Two data rows.
    assert len([line for line in result.output.splitlines() if line]) == 3


def test_query_honours_action_filter(tmp_path: Path) -> None:
    """Filter narrows the count_by_action output in the rendered report."""
    feed = tmp_path / "audit.jsonl"
    _write_chain(feed, n=3)

    result = CliRunner().invoke(
        main,
        [
            "query",
            "--tenant",
            _TENANT_A,
            "--source",
            str(feed),
            "--workspace",
            str(tmp_path / "qws"),
            "--action",
            "episode_appended",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["total"] == 3


def test_query_chain_break_exits_two(tmp_path: Path) -> None:
    """Chain tamper → exit code 2 (distinct from 0 clean / 1 tooling)."""
    feed = tmp_path / "audit.jsonl"
    _write_chain(feed, n=3)
    # Mutate the file post-hash: replace one entry_hash to break the chain.
    text = feed.read_text()
    lines = text.splitlines()
    # Trim the last 64 chars of entry_hash on line 1 and replace with zeros.
    record = json.loads(lines[1])
    record["entry_hash"] = "0" * 64
    lines[1] = json.dumps(record)
    feed.write_text("\n".join(lines) + "\n")

    result = CliRunner().invoke(
        main,
        [
            "query",
            "--tenant",
            _TENANT_A,
            "--source",
            str(feed),
            "--workspace",
            str(tmp_path / "qws"),
        ],
    )
    assert result.exit_code == 2, result.output
    assert "Chain BROKEN" in result.output or "tamper" in result.output.lower()
