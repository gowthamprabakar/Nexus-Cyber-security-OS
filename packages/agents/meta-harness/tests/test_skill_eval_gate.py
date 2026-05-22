"""Tests — `meta_harness.skill_eval_gate` (Task 8).

14 tests covering the Option-B mandatory eval-gate:

1.  ``with_candidate_skill_overlay`` sets the ContextVar;
    ``get_active_skill_overlay`` reads it back.
2.  Exiting the CM restores the prior value.
3.  Exiting via exception still restores the prior value.
4.  Nested overlays restore correctly (inner masks outer; outer
    restored on inner exit).
5.  ``compute_per_agent_overlay_dir`` returns the Q1 layout.
6.  ``compute_eval_gate_result_path`` sits alongside SKILL.md.
7.  ``compute_per_case_regressions`` returns ``()`` when results match.
8.  passed→failed flip produces a single ``(case_id, 100.0)`` entry.
9.  failed→passed improvement produces NO entry (only regressions are
    reported).
10. Missing-from-candidate cases that passed in baseline are treated
    as full regressions (drop=100.0).
11. ``evaluate_gate`` returns False when overall pass-rate dropped.
12. ``evaluate_gate`` returns False when any per-case drop ≥ 5 pct.
13. ``cache_eval_gate_result`` round-trips through
    ``load_cached_eval_gate_result``; missing cache returns ``None``.
14. ``run_skill_eval_gate`` end-to-end with a ``FakeRunner`` — empty
    cases raise ``SkillEvalGateError``; baseline+candidate runs both
    execute; returned ``EvalGateResult`` carries the verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from eval_framework.cases import EvalCase
from eval_framework.runner import FakeRunner
from meta_harness.schemas import (
    EvalGateResult,
    Skill,
    SkillCandidate,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)
from meta_harness.skill_eval_gate import (
    PER_CASE_REGRESSION_THRESHOLD_PCT,
    SkillEvalGateError,
    cache_eval_gate_result,
    compute_eval_gate_result_path,
    compute_per_agent_overlay_dir,
    compute_per_case_regressions,
    evaluate_gate,
    get_active_skill_overlay,
    load_cached_eval_gate_result,
    run_skill_eval_gate,
    with_candidate_skill_overlay,
)

pytestmark = pytest.mark.asyncio

_EVALUATED_AT = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)


def _suite_result_from_cases(
    cases: list[tuple[str, bool]],
    *,
    runner_name: str = "investigation",
    suite_id: str = "s1",
) -> object:
    """Build a SuiteResult-like object from (case_id, passed) tuples.

    Uses pydantic so the property accessors (`pass_rate`, etc.) work.
    """
    from eval_framework.results import EvalResult, SuiteResult
    from eval_framework.trace import EvalTrace

    eval_results = [
        EvalResult(
            case_id=case_id,
            runner=runner_name,
            passed=passed,
            failure_reason=None if passed else "fixture_failure",
            duration_sec=0.01,
            trace=EvalTrace(),
        )
        for case_id, passed in cases
    ]
    return SuiteResult(
        suite_id=suite_id,
        runner=runner_name,
        started_at=_EVALUATED_AT,
        completed_at=_EVALUATED_AT,
        cases=eval_results,
    )


def _candidate(
    *,
    skill_id: str = "iam-privesc/aws_iam_privesc_via_assumed_role",
    target_agent: str = "investigation",
    category: str = "iam-privesc",
    name: str = "aws_iam_privesc_via_assumed_role",
) -> SkillCandidate:
    skill = Skill(
        name=name,
        description="x",
        version="0.1.0",
        platforms=("nexus",),
        target_agent=target_agent,
        category=category,
        created_by="meta_harness@v0.2.0",
        provenance=(),
        eval_gate_status=SkillEvalGateStatus.NOT_RUN,
        deployment_status=SkillDeploymentStatus.CANDIDATE,
        body="body",
    )
    return SkillCandidate(
        skill_id=skill_id,
        skill=skill,
        shadow_path=f"/ws/.nexus/candidate-skills/{target_agent}/{skill_id}/SKILL.md",
        tool_sequence_hash="abc123",
        emitted_at=_EVALUATED_AT,
    )


# ---------------------------- ContextVar overlay binding ----------------------------


async def test_with_candidate_skill_overlay_sets_and_reads_back(tmp_path: Path) -> None:
    assert get_active_skill_overlay() is None
    with with_candidate_skill_overlay(tmp_path):
        assert get_active_skill_overlay() == tmp_path
    assert get_active_skill_overlay() is None


async def test_with_candidate_skill_overlay_restores_on_normal_exit(tmp_path: Path) -> None:
    with with_candidate_skill_overlay(tmp_path):
        pass
    assert get_active_skill_overlay() is None


async def test_with_candidate_skill_overlay_restores_on_exception(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="probe"), with_candidate_skill_overlay(tmp_path):
        raise RuntimeError("probe")
    assert get_active_skill_overlay() is None


async def test_with_candidate_skill_overlay_nested_restores_outer(tmp_path: Path) -> None:
    outer = tmp_path / "outer"
    inner = tmp_path / "inner"
    with with_candidate_skill_overlay(outer):
        assert get_active_skill_overlay() == outer
        with with_candidate_skill_overlay(inner):
            assert get_active_skill_overlay() == inner
        assert get_active_skill_overlay() == outer
    assert get_active_skill_overlay() is None


# ---------------------------- path helpers ----------------------------


async def test_compute_per_agent_overlay_dir_layout(tmp_path: Path) -> None:
    assert (
        compute_per_agent_overlay_dir(workspace_root=tmp_path, agent_id="investigation")
        == tmp_path / ".nexus" / "candidate-skills" / "investigation"
    )


async def test_compute_eval_gate_result_path_layout(tmp_path: Path) -> None:
    assert (
        compute_eval_gate_result_path(
            workspace_root=tmp_path,
            agent_id="investigation",
            skill_id="iam-privesc/role-chain",
        )
        == tmp_path
        / ".nexus"
        / "candidate-skills"
        / "investigation"
        / "iam-privesc"
        / "role-chain"
        / "eval_gate_result.json"
    )


# ---------------------------- compute_per_case_regressions ----------------------------


async def test_per_case_regressions_empty_when_results_match() -> None:
    cases = [("c1", True), ("c2", True), ("c3", False)]
    baseline = _suite_result_from_cases(cases)
    candidate = _suite_result_from_cases(cases)
    assert compute_per_case_regressions(baseline, candidate) == ()


async def test_per_case_regressions_reports_passed_to_failed_flip() -> None:
    baseline = _suite_result_from_cases([("c1", True), ("c2", True)])
    candidate = _suite_result_from_cases([("c1", True), ("c2", False)])
    assert compute_per_case_regressions(baseline, candidate) == (("c2", 100.0),)


async def test_per_case_regressions_skips_failed_to_passed_improvement() -> None:
    baseline = _suite_result_from_cases([("c1", False)])
    candidate = _suite_result_from_cases([("c1", True)])
    assert compute_per_case_regressions(baseline, candidate) == ()


async def test_per_case_regressions_treats_missing_candidate_case_as_regression() -> None:
    baseline = _suite_result_from_cases([("c1", True), ("c2", True)])
    candidate = _suite_result_from_cases([("c1", True)])  # c2 missing
    assert compute_per_case_regressions(baseline, candidate) == (("c2", 100.0),)


# ---------------------------- evaluate_gate ----------------------------


async def test_evaluate_gate_fails_on_overall_pass_rate_drop() -> None:
    assert (
        evaluate_gate(
            baseline_pass_rate=0.9,
            candidate_pass_rate=0.8,
            per_case_regressions=(),
        )
        is False
    )


async def test_evaluate_gate_fails_on_per_case_regression_at_or_above_threshold() -> None:
    assert (
        evaluate_gate(
            baseline_pass_rate=0.5,
            candidate_pass_rate=1.0,  # overall improved
            per_case_regressions=(("c1", PER_CASE_REGRESSION_THRESHOLD_PCT),),
        )
        is False
    )


# ---------------------------- cache / load round-trip ----------------------------


async def test_cache_and_load_eval_gate_result_round_trip(tmp_path: Path) -> None:
    result = EvalGateResult(
        skill_id="iam-privesc/role-chain",
        target_agent="investigation",
        baseline_pass_rate=0.8,
        candidate_pass_rate=0.9,
        per_case_regressions=(),
        passed=True,
        evaluated_at=_EVALUATED_AT,
    )
    written = cache_eval_gate_result(
        result,
        workspace_root=tmp_path,
        agent_id="investigation",
        skill_id="iam-privesc/role-chain",
    )
    assert written.is_file()

    loaded = load_cached_eval_gate_result(
        workspace_root=tmp_path,
        agent_id="investigation",
        skill_id="iam-privesc/role-chain",
    )
    assert loaded == result

    missing = load_cached_eval_gate_result(
        workspace_root=tmp_path,
        agent_id="investigation",
        skill_id="never/written",
    )
    assert missing is None


# ---------------------------- run_skill_eval_gate (end-to-end) ----------------------------


async def test_run_skill_eval_gate_empty_cases_raises(tmp_path: Path) -> None:
    with pytest.raises(SkillEvalGateError, match=r"requires non-empty cases"):
        await run_skill_eval_gate(
            candidate=_candidate(),
            workspace_root=tmp_path,
            cases=[],
            runner=FakeRunner(agent_name="investigation"),
            evaluated_at=_EVALUATED_AT,
        )


async def test_run_skill_eval_gate_end_to_end_with_fake_runner(tmp_path: Path) -> None:
    cases = [
        EvalCase(case_id="c_pass", suite="investigation", description="x", inputs={}),
        EvalCase(case_id="c_fail", suite="investigation", description="x", inputs={}),
    ]
    runner = FakeRunner(agent_name="investigation", default_passed=True)
    runner.queue("c_fail", passed=False, failure_reason="stub_fail")

    result = await run_skill_eval_gate(
        candidate=_candidate(),
        workspace_root=tmp_path,
        cases=cases,
        runner=runner,
        evaluated_at=_EVALUATED_AT,
    )
    assert isinstance(result, EvalGateResult)
    assert result.skill_id == "iam-privesc/aws_iam_privesc_via_assumed_role"
    assert result.target_agent == "investigation"
    # FakeRunner is deterministic — baseline and candidate both pass c_pass + fail c_fail.
    assert result.baseline_pass_rate == 0.5
    assert result.candidate_pass_rate == 0.5
    assert result.per_case_regressions == ()
    assert result.passed is True
