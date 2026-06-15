"""Tests for `AppSecEvalRunner` — the D.14 agent's `EvalRunner` Protocol impl (B-1 PR10)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from appsec.eval_runner import AppSecEvalRunner
from eval_framework.cases import EvalCase, load_cases
from eval_framework.runner import EvalRunner
from eval_framework.suite import run_suite

_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105  AWS docs example, test fixture


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


def _iac() -> dict[str, Any]:
    return {
        "check_id": "CKV_AWS_20",
        "check_name": "S3 public ACL",
        "file_path": "/main.tf",
        "file_line_range": [1, 5],
        "resource": "aws_s3_bucket.x",
        "severity": "HIGH",
    }


def _sast() -> dict[str, Any]:
    return {
        "check_id": "python.lang.security.dangerous-exec",
        "path": "src/app.py",
        "start": {"line": 42},
        "extra": {"message": "exec()", "severity": "ERROR"},
    }


def _secret() -> dict[str, Any]:
    return {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "src/config.py",
        "StartLine": 12,
        "EndLine": 12,
        "Secret": _SECRET,
        "Match": f"KEY={_SECRET}",
    }


# ---------------------------- Protocol shape -----------------------------


def test_runner_satisfies_eval_runner_protocol() -> None:
    assert isinstance(AppSecEvalRunner(), EvalRunner)


def test_runner_agent_name_is_stable() -> None:
    assert AppSecEvalRunner().agent_name == "appsec"


# ---------------------------- empty fixture ------------------------------


@pytest.mark.asyncio
async def test_empty_fixture_produces_zero_findings(tmp_path: Path) -> None:
    runner = AppSecEvalRunner()
    case = _case("empty", expected={"finding_count": 0, "code_secret_count": 0})
    passed, reason, actuals, audit_log_path = await runner.run(case, workspace=tmp_path)

    assert passed is True, reason
    assert actuals["finding_count"] == 0
    assert actuals["code_secret_count"] == 0
    assert audit_log_path is not None and audit_log_path.exists()


# ---------------------------- discriminators -----------------------------


@pytest.mark.asyncio
async def test_iac_and_sast_carry_distinct_discriminators(tmp_path: Path) -> None:
    runner = AppSecEvalRunner()
    case = _case(
        "mix",
        fixture={"checkov_failed_checks": [_iac()], "semgrep_results": [_sast()]},
        expected={
            "finding_count": 2,
            "by_type": {"appsec_iac_misconfiguration": 1, "appsec_sast_finding": 1},
        },
    )
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)

    assert passed is True, reason
    assert actuals["by_type"] == {"appsec_iac_misconfiguration": 1, "appsec_sast_finding": 1}


@pytest.mark.asyncio
async def test_secret_routes_to_handoff_not_findings(tmp_path: Path) -> None:
    runner = AppSecEvalRunner()
    case = _case(
        "secret",
        fixture={"gitleaks_hits": [_secret()]},
        expected={"finding_count": 0, "code_secret_count": 1},
    )
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)

    assert passed is True, reason
    assert actuals["finding_count"] == 0
    assert actuals["code_secret_count"] == 1


# ---------------------------- mismatch paths -----------------------------


@pytest.mark.asyncio
async def test_count_mismatch_marks_failed(tmp_path: Path) -> None:
    runner = AppSecEvalRunner()
    case = _case("count_off", fixture={"semgrep_results": [_sast()]}, expected={"finding_count": 5})
    passed, reason, _, _ = await runner.run(case, workspace=tmp_path)

    assert passed is False
    assert reason is not None and "finding_count" in reason


@pytest.mark.asyncio
async def test_by_type_mismatch_marks_failed(tmp_path: Path) -> None:
    runner = AppSecEvalRunner()
    case = _case(
        "type_off",
        fixture={"semgrep_results": [_sast()]},
        expected={"by_type": {"appsec_iac_misconfiguration": 1}},
    )
    passed, reason, _, _ = await runner.run(case, workspace=tmp_path)

    assert passed is False
    assert reason is not None and "by_type" in reason


@pytest.mark.asyncio
async def test_secret_count_mismatch_marks_failed(tmp_path: Path) -> None:
    runner = AppSecEvalRunner()
    case = _case(
        "secret_off",
        fixture={"gitleaks_hits": [_secret()]},
        expected={"code_secret_count": 0},
    )
    passed, reason, _, _ = await runner.run(case, workspace=tmp_path)

    assert passed is False
    assert reason is not None and "code_secret_count" in reason


# ---------------------------- suite acceptance ---------------------------


@pytest.mark.asyncio
async def test_all_shipped_cases_pass_through_run_suite(tmp_path: Path) -> None:
    """The shipped YAML cases under packages/agents/appsec/eval/cases all pass.

    The D.14 acceptance gate — same shape as the vulnerability / cloud-posture
    gates; confirms ADR-007's entry-point-registered EvalRunner pattern extends to
    AppSec.
    """
    cases_dir = Path(__file__).resolve().parents[1] / "eval" / "cases"
    cases = load_cases(cases_dir)
    assert len(cases) == 6

    suite = await run_suite(cases, AppSecEvalRunner(), workspace_root=tmp_path)

    failures = [(c.case_id, c.failure_reason) for c in suite.cases if not c.passed]
    assert suite.passed == 6, f"failures: {failures}"
    assert suite.runner == "appsec"
    assert all(c.trace.audit_log_path is not None for c in suite.cases)
    assert all(c.trace.audit_chain_valid for c in suite.cases)
