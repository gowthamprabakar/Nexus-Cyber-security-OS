"""Tests for `CloudPostureEvalRunner` — the agent's `EvalRunner` Protocol impl."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cloud_posture.eval_runner import CloudPostureEvalRunner
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner
from eval_framework.suite import run_suite


def _case(
    case_id: str = "001_smoke",
    *,
    fixture: dict[str, Any] | None = None,
    expected: dict[str, Any] | None = None,
) -> EvalCase:
    return EvalCase(
        case_id=case_id,
        description=f"runner test {case_id}",
        fixture=fixture or {},
        expected=expected or {},
    )


# ---------------------------- Protocol shape -----------------------------


def test_runner_satisfies_eval_runner_protocol() -> None:
    assert isinstance(CloudPostureEvalRunner(), EvalRunner)


def test_runner_agent_name_is_stable() -> None:
    assert CloudPostureEvalRunner().agent_name == "cloud_posture"


# ---------------------------- Empty fixture ------------------------------


@pytest.mark.asyncio
async def test_empty_fixture_produces_zero_findings(tmp_path: Path) -> None:
    runner = CloudPostureEvalRunner()
    case = _case(
        "empty",
        fixture={},
        expected={"finding_count": 0},
    )
    passed, reason, actuals, audit_log_path = await runner.run(case, workspace=tmp_path)

    assert passed is True
    assert reason is None
    assert actuals.get("finding_count") == 0
    assert audit_log_path is not None
    assert audit_log_path.exists()


# ---------------------------- IAM no-MFA fixture -------------------------


@pytest.mark.asyncio
async def test_no_mfa_user_yields_one_high_finding(tmp_path: Path) -> None:
    runner = CloudPostureEvalRunner()
    case = _case(
        "no_mfa",
        fixture={"iam_users_without_mfa": ["alice"]},
        expected={"finding_count": 1, "has_severity": {"high": 1}},
    )

    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)

    assert passed is True, reason
    assert actuals["finding_count"] == 1
    assert actuals["by_severity"].get("high") == 1


# ---------------------------- Mismatch path -------------------------------


@pytest.mark.asyncio
async def test_mismatched_count_marks_case_failed(tmp_path: Path) -> None:
    runner = CloudPostureEvalRunner()
    case = _case(
        "mismatch",
        fixture={"iam_users_without_mfa": ["alice", "bob"]},
        expected={"finding_count": 5},  # actual will be 2
    )

    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed is False
    assert reason is not None
    assert "finding_count" in reason
    assert actuals["finding_count"] == 2


@pytest.mark.asyncio
async def test_mismatched_severity_marks_case_failed(tmp_path: Path) -> None:
    runner = CloudPostureEvalRunner()
    case = _case(
        "sev",
        fixture={"iam_users_without_mfa": ["alice"]},
        expected={"finding_count": 1, "has_severity": {"critical": 1}},  # actual high
    )

    passed, reason, _, _ = await runner.run(case, workspace=tmp_path)
    assert passed is False
    assert reason is not None
    assert "severity" in reason


# ---------------------------- Suite acceptance ---------------------------


@pytest.mark.asyncio
async def test_all_ten_shipped_cases_pass_through_run_suite(tmp_path: Path) -> None:
    """The 10 YAML cases under packages/agents/cloud-posture/eval/cases all pass.

    This is the regression-guard handover from `_eval_local`: the new
    `CloudPostureEvalRunner` produces the same outcome on every case.
    """
    from eval_framework.cases import load_cases

    cases_dir = Path(__file__).resolve().parents[1] / "eval" / "cases"
    cases = load_cases(cases_dir)
    assert len(cases) == 10

    suite = await run_suite(cases, CloudPostureEvalRunner(), workspace_root=tmp_path)

    failures = [(c.case_id, c.failure_reason) for c in suite.cases if not c.passed]
    assert suite.passed == 10, f"failures: {failures}"
    assert suite.runner == "cloud_posture"
    # Each case should have an audit log captured.
    assert all(c.trace.audit_log_path is not None for c in suite.cases)
    assert all(c.trace.audit_chain_valid for c in suite.cases)
