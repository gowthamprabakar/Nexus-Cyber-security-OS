"""Tests for `AuditEvalRunner` (F.6 Task 14).

Production contract:

- Conforms to the `eval_framework.runner.EvalRunner` Protocol.
- `agent_name == "audit"` — matches the pyproject entry-point name.
- Registered via `nexus_eval_runners` entry-point so
  `eval-framework run --runner audit` resolves to this class.
- Interprets the F.6 YAML fixture schema (jsonl_events, memory_events,
  tampered_jsonl_index, query, nl_query, llm_response) and drives
  `audit.agent.run` against an in-memory aiosqlite store.
- All 10 shipped YAML cases pass.
- Emits the run's audit log to `<workspace>/audit.jsonl` per the
  eval-framework's audit-trail contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from audit.eval_runner import AuditEvalRunner
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def _load_case(case_file: Path) -> EvalCase:
    raw = yaml.safe_load(case_file.read_text())
    return EvalCase(
        case_id=raw["case_id"],
        description=raw.get("description", ""),
        fixture=raw.get("fixture") or {},
        expected=raw.get("expected") or {},
    )


# ---------------------------- protocol + name ---------------------------


def test_audit_eval_runner_is_an_eval_runner() -> None:
    runner = AuditEvalRunner()
    assert isinstance(runner, EvalRunner)


def test_audit_eval_runner_agent_name_matches_entry_point() -> None:
    runner = AuditEvalRunner()
    assert runner.agent_name == "audit"


def test_audit_entry_point_resolves_to_runner() -> None:
    from importlib.metadata import entry_points

    eps = entry_points(group="nexus_eval_runners")
    audit_ep = next(ep for ep in eps if ep.name == "audit")
    loaded = audit_ep.load()
    assert loaded is AuditEvalRunner


# ---------------------------- case execution ---------------------------


@pytest.mark.asyncio
async def test_runner_executes_empty_corpus_case(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "001_empty_corpus.yaml")
    outcome = await AuditEvalRunner().run(case, workspace=tmp_path)
    passed, reason, actuals, _audit_log_path = outcome
    assert passed, reason
    assert actuals["total"] == 0


@pytest.mark.asyncio
async def test_runner_executes_clean_chain_case(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "002_clean_chain_ingest.yaml")
    passed, reason, actuals, _ = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["total"] == 3
    assert actuals["chain_valid"] is True


@pytest.mark.asyncio
async def test_runner_detects_tampered_chain(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "003_tampered_chain_detected.yaml")
    passed, reason, actuals, _ = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["chain_valid"] is False


@pytest.mark.asyncio
async def test_runner_applies_action_filter(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "004_per_action_query.yaml")
    passed, reason, actuals, _ = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["count_by_action"] == {"entity_upserted": 2}


@pytest.mark.asyncio
async def test_runner_enforces_tenant_isolation(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "005_tenant_isolation.yaml")
    passed, reason, actuals, _ = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["total"] == 1


@pytest.mark.asyncio
async def test_runner_merges_cross_sources(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "006_cross_source_merge.yaml")
    passed, reason, actuals, _ = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["total"] == 3


@pytest.mark.asyncio
async def test_runner_honours_time_range_filter(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "007_time_range_filter.yaml")
    passed, reason, actuals, _ = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["total"] == 1


@pytest.mark.asyncio
async def test_runner_honours_agent_id_filter(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "008_agent_id_filter.yaml")
    passed, reason, actuals, _ = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["total"] == 2


@pytest.mark.asyncio
async def test_runner_walks_correlation_id(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "009_correlation_id_walk.yaml")
    passed, reason, actuals, _ = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["total"] == 3


@pytest.mark.asyncio
async def test_runner_translates_nl_query(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "010_nl_query_translation.yaml")
    passed, reason, actuals, _ = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["total"] == 2


# ---------------------------- full 10/10 acceptance ---------------------


@pytest.mark.asyncio
async def test_all_10_shipped_cases_pass(tmp_path: Path) -> None:
    """The full 10/10 acceptance gate for F.6."""
    case_files = sorted(_CASES_DIR.glob("*.yaml"))
    assert len(case_files) == 10, f"F.6 ships exactly 10 eval cases; got {len(case_files)}"

    runner = AuditEvalRunner()
    failures: list[str] = []
    for cf in case_files:
        case = _load_case(cf)
        workspace = tmp_path / case.case_id
        passed, reason, _, _ = await runner.run(case, workspace=workspace)
        if not passed:
            failures.append(f"{case.case_id}: {reason}")

    assert not failures, "\n".join(failures)


# ---------------------------- audit log emission ------------------------


@pytest.mark.asyncio
async def test_runner_emits_audit_log_path(tmp_path: Path) -> None:
    """The eval framework consumes the audit log path as the run's trace."""
    case = _load_case(_CASES_DIR / "002_clean_chain_ingest.yaml")
    _, _, _, audit_log_path = await AuditEvalRunner().run(case, workspace=tmp_path)
    assert audit_log_path is not None
    assert audit_log_path.is_file()
