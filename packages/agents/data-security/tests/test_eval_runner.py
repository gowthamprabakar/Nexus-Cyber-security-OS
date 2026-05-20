"""Tests — ``data_security.eval_runner`` + the 10-case acceptance gate.

Task 14. The single critical assertion: **10/10 eval cases pass**. This is
the operator-facing acceptance gate per the plan §"Done definition".
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from data_security.eval_runner import DataSecurityEvalRunner
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner

CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def _load_case(path: Path) -> EvalCase:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return EvalCase.model_validate(raw)


def _all_case_paths() -> list[Path]:
    return sorted(CASES_DIR.glob("*.yaml"))


# ---------------------------- protocol satisfaction ----------------------


def test_runner_satisfies_protocol() -> None:
    runner = DataSecurityEvalRunner()
    assert isinstance(runner, EvalRunner)
    assert runner.agent_name == "data_security"


# ---------------------------- structural -----------------------------------


def test_ten_cases_on_disk() -> None:
    """Plan §"Execution status" Task 13: 10 representative YAML eval cases."""
    paths = _all_case_paths()
    assert len(paths) == 10, f"expected 10 eval cases, found {len(paths)}"


def test_eval_cases_cover_all_4_detectors_plus_correlation() -> None:
    """Cases collectively exercise every detector + the F.3 correlation path."""
    case_ids = {p.stem for p in _all_case_paths()}
    expected = {
        "001_clean_account",
        "002_public_bucket_no_pii",
        "003_public_bucket_with_pii_critical",
        "004_unencrypted_with_pii",
        "005_sensitive_location_violation",
        "006_oversharing_iam_no_pii",
        "007_oversharing_iam_with_pii",
        "008_correlation_uplift_from_f3",
        "009_no_correlation_workspace_absent",
        "010_no_pii_leak_in_report",
    }
    assert case_ids == expected


def test_q6_acceptance_case_carries_forbidden_strings() -> None:
    """Case 010 is the system-level Q6 acceptance probe; it must carry the
    raw PII strings as ``expected.no_pii_strings``.
    """
    case = _load_case(CASES_DIR / "010_no_pii_leak_in_report.yaml")
    forbidden = case.expected.get("no_pii_strings", [])
    assert "987-65-4321" in forbidden
    assert "4111-1111-1111-1111" in forbidden


# ---------------------------- happy + mismatch synthetics ---------------


@pytest.mark.asyncio
async def test_run_empty_case_yields_pass(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_empty",
        description="empty inputs",
        fixture={"buckets": [], "objects": []},
        expected={"finding_count": 0},
    )
    passed, reason, actuals, audit = await DataSecurityEvalRunner().run(case, workspace=tmp_path)
    assert passed is True
    assert reason is None
    assert actuals["finding_count"] == 0
    assert audit is not None and audit.is_file()


@pytest.mark.asyncio
async def test_run_finding_count_mismatch_returns_failure_reason(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_count_mismatch",
        description="empty but expects one finding",
        fixture={"buckets": [], "objects": []},
        expected={"finding_count": 1},
    )
    passed, reason, _actuals, _audit = await DataSecurityEvalRunner().run(case, workspace=tmp_path)
    assert passed is False
    assert reason is not None
    assert "finding_count" in reason


# ---------------------------- 10/10 acceptance gate ---------------------


@pytest.mark.parametrize("case_path", _all_case_paths(), ids=lambda p: p.stem)
@pytest.mark.asyncio
async def test_case_passes(case_path: Path, tmp_path: Path) -> None:
    """**LOAD-BEARING ACCEPTANCE GATE.** Every individual eval case must pass.

    Per the plan §"Done definition": ``eval-framework run --runner
    data_security`` must return 10/10. This parametrized test is the
    test-level equivalent.
    """
    case = _load_case(case_path)
    passed, reason, actuals, _ = await DataSecurityEvalRunner().run(case, workspace=tmp_path)
    assert passed, f"case {case.case_id} failed: {reason}; actuals={actuals}"


# ---------------------------- entry-point discovery ---------------------


def test_eval_runner_entry_point_discoverable() -> None:
    """``eval-framework run --runner data_security`` resolves through this entry-point."""
    from importlib.metadata import entry_points

    eps = entry_points(group="nexus_eval_runners")
    matched = [ep for ep in eps if ep.name == "data_security"]
    assert len(matched) == 1, f"expected one data_security entry-point, got {len(matched)}"
    klass = matched[0].load()
    assert klass is DataSecurityEvalRunner
