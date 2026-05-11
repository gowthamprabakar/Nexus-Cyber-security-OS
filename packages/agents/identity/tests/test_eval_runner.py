"""Tests for `identity.eval_runner.IdentityEvalRunner`.

Two surfaces tested:

1. Protocol satisfaction + happy/mismatch shape of one synthetic case.
2. The 10/10 acceptance gate against the YAMLs in `eval/cases/`.

The eval-framework's `run_suite` is the end-to-end happy path; here we
call the runner directly per case so failures are easy to localize.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner
from identity.eval_runner import IdentityEvalRunner

CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def _load_case(path: Path) -> EvalCase:
    raw = yaml.safe_load(path.read_text())
    return EvalCase.model_validate(raw)


# ---------------------------- protocol satisfaction ----------------------


def test_runner_satisfies_protocol() -> None:
    runner = IdentityEvalRunner()
    assert isinstance(runner, EvalRunner)
    assert runner.agent_name == "identity"


# ---------------------------- happy path on a synthetic case -------------


@pytest.mark.asyncio
async def test_run_clean_account_yields_pass(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_clean",
        description="empty inventory",
        fixture={"iam_listing": {"users": [], "roles": [], "groups": []}},
        expected={"finding_count": 0},
    )
    runner = IdentityEvalRunner()
    passed, reason, actuals, audit = await runner.run(case, workspace=tmp_path)

    assert passed is True
    assert reason is None
    assert actuals["finding_count"] == 0
    assert audit is not None and audit.is_file()


@pytest.mark.asyncio
async def test_run_mismatch_returns_failure_reason(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_mismatch",
        description="empty inventory but expected one finding",
        fixture={"iam_listing": {"users": [], "roles": [], "groups": []}},
        expected={"finding_count": 1},
    )
    passed, reason, _, _ = await IdentityEvalRunner().run(case, workspace=tmp_path)
    assert passed is False
    assert reason is not None
    assert "finding_count" in reason


@pytest.mark.asyncio
async def test_run_severity_mismatch_returns_failure_reason(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_sev_mismatch",
        description="admin no MFA but expecting wrong severity count",
        fixture={
            "iam_listing": {
                "users": [
                    {
                        "arn": "arn:aws:iam::123456789012:user/x",
                        "name": "x",
                        "attached_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                    }
                ],
                "roles": [],
                "groups": [],
            }
        },
        expected={"by_severity": {"critical": 99}},
    )
    passed, reason, _, _ = await IdentityEvalRunner().run(case, workspace=tmp_path)
    assert passed is False
    assert reason is not None
    assert "critical" in reason


# ---------------------------- 10/10 acceptance gate ----------------------


def _all_case_paths() -> list[Path]:
    return sorted(CASES_DIR.glob("*.yaml"))


def test_ten_cases_on_disk() -> None:
    paths = _all_case_paths()
    assert len(paths) == 10, f"expected 10 eval cases, found {len(paths)}"


@pytest.mark.parametrize("case_path", _all_case_paths(), ids=lambda p: p.stem)
@pytest.mark.asyncio
async def test_case_passes(case_path: Path, tmp_path: Path) -> None:
    """Each on-disk YAML case must pass against `IdentityEvalRunner`."""
    case = _load_case(case_path)
    passed, reason, actuals, _ = await IdentityEvalRunner().run(case, workspace=tmp_path)
    assert passed, f"case {case.case_id} failed: {reason}; actuals={actuals}"
