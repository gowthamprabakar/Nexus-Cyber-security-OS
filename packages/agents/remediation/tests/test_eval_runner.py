"""Tests for `RemediationEvalRunner` — fixture parsing + the v0.1 acceptance gate.

The cornerstone test is `test_v0_1_acceptance_suite` which loads cases 001-010
from `eval/cases/*.yaml`, runs them through the runner, and asserts every one
passes. That is the v0.1 acceptance gate.

Cases 011-015 (the promotion-surface cases from A.1 v0.1.1 Task 10) live in
the same directory but are not yet executable — the runner's
`fixture.promotion` parser, the `REFUSED_PROMOTION_GATE` outcome, and the
`by_promotion_proposal` / `reconcile_matches` assertions all land in Task 12.
Until then `test_v0_1_1_promotion_cases_load` verifies the 5 YAMLs parse as
valid `EvalCase` objects (catches schema drift early), and execution is
deferred. Task 12 will fold them into the acceptance suite as 15/15.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from eval_framework.cases import EvalCase, load_case_file, load_cases
from remediation.eval_runner import RemediationEvalRunner

CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"

_V0_1_ACCEPTANCE_IDS: tuple[str, ...] = (
    "001_clean",
    "002_single_action_recommend",
    "003_single_action_dry_run",
    "004_single_action_execute_validated",
    "005_single_action_execute_rolled_back",
    "006_unauthorized_action_refused",
    "007_unauthorized_mode_refused",
    "008_blast_radius_cap",
    "009_multi_finding_batch",
    "010_mixed_action_classes",
)

_V0_1_1_PENDING_TASK_12_IDS: tuple[str, ...] = (
    "011_promotion_blocked_at_stage_1",
    "012_promotion_blocked_at_stage_2",
    "013_promotion_mixed_per_finding",
    "014_promotion_advance_proposed",
    "015_reconcile_round_trip",
)


@pytest.mark.asyncio
async def test_runner_agent_name() -> None:
    runner = RemediationEvalRunner()
    assert runner.agent_name == "remediation"


@pytest.mark.asyncio
async def test_v0_1_acceptance_suite(tmp_path: Path) -> None:
    """The v0.1 acceptance gate — cases 001-010 must all pass.

    Cases 011-015 are skipped (executable in Task 12). If any v0.1 case fails,
    the runner's contract is broken — either the agent driver regressed or a
    case's fixture/expected drifted from the implementation.
    """
    cases = load_cases(CASES_DIR)
    case_ids = {c.case_id for c in cases}

    missing_v0_1 = set(_V0_1_ACCEPTANCE_IDS) - case_ids
    assert not missing_v0_1, (
        f"v0.1 acceptance cases missing from {CASES_DIR}: {sorted(missing_v0_1)}"
    )

    missing_v0_1_1 = set(_V0_1_1_PENDING_TASK_12_IDS) - case_ids
    assert not missing_v0_1_1, (
        f"v0.1.1 promotion-surface cases missing from {CASES_DIR}: {sorted(missing_v0_1_1)}"
    )

    runner = RemediationEvalRunner()
    failures: list[str] = []
    for case in cases:
        if case.case_id not in _V0_1_ACCEPTANCE_IDS:
            continue
        case_workspace = tmp_path / case.case_id
        passed, reason, actuals, _ = await runner.run(case, workspace=case_workspace)
        if not passed:
            failures.append(f"{case.case_id}: {reason} (actuals={actuals})")

    assert not failures, "v0.1 eval suite failed:\n  " + "\n  ".join(failures)


def test_v0_1_1_promotion_cases_load() -> None:
    """Cases 011-015 must parse as valid `EvalCase` objects ahead of Task 12.

    Catches YAML / schema drift early. Execution is deferred to Task 12,
    which wires the `fixture.promotion` parser, the `REFUSED_PROMOTION_GATE`
    outcome, the `by_promotion_proposal` actuals key, and the
    `reconcile_matches` assertion through the runner. At that point this test
    and `test_v0_1_acceptance_suite` collapse into a single 15/15 acceptance
    gate.
    """
    for case_id in _V0_1_1_PENDING_TASK_12_IDS:
        path = CASES_DIR / f"{case_id}.yaml"
        assert path.exists(), f"{case_id}.yaml missing in {CASES_DIR}"
        case = load_case_file(path)
        assert case.case_id == case_id, f"case_id mismatch in {path.name}"
        promotion = case.fixture.get("promotion")
        assert isinstance(promotion, dict), (
            f"{case_id}.yaml fixture.promotion missing or not a mapping"
        )
        assert promotion.get("schema_version") == "0.1", (
            f"{case_id}.yaml fixture.promotion.schema_version must be '0.1'"
        )
        assert case.expected, f"{case_id}.yaml expected section is empty"


# ---------------------------- per-case smoke tests ------------------------


@pytest.mark.asyncio
async def test_clean_case_returns_zero_findings(tmp_path: Path) -> None:
    case = _load_case("001_clean.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["finding_count"] == 0


@pytest.mark.asyncio
async def test_recommend_mode_produces_one_recommended_only(tmp_path: Path) -> None:
    case = _load_case("002_single_action_recommend.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["by_outcome"]["recommended_only"] == 1


@pytest.mark.asyncio
async def test_dry_run_mode_produces_one_dry_run_only(tmp_path: Path) -> None:
    case = _load_case("003_single_action_dry_run.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["by_outcome"]["dry_run_only"] == 1


@pytest.mark.asyncio
async def test_execute_validated_path(tmp_path: Path) -> None:
    case = _load_case("004_single_action_execute_validated.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["by_outcome"]["executed_validated"] == 1


@pytest.mark.asyncio
async def test_execute_rolled_back_path(tmp_path: Path) -> None:
    case = _load_case("005_single_action_execute_rolled_back.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["by_outcome"]["executed_rolled_back"] == 1


@pytest.mark.asyncio
async def test_unauthorized_action_refused(tmp_path: Path) -> None:
    case = _load_case("006_unauthorized_action_refused.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    # Case 006 has two findings — one with no v0.1 action class, one with an
    # unauthorised action class — both refused.
    assert actuals["by_outcome"]["refused_unauthorized"] == 2


@pytest.mark.asyncio
async def test_unauthorized_mode_raises(tmp_path: Path) -> None:
    case = _load_case("007_unauthorized_mode_refused.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals.get("raised") == "AuthorizationError"


@pytest.mark.asyncio
async def test_blast_radius_cap(tmp_path: Path) -> None:
    case = _load_case("008_blast_radius_cap.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["by_outcome"]["refused_blast_radius"] == 1


@pytest.mark.asyncio
async def test_multi_finding_batch(tmp_path: Path) -> None:
    case = _load_case("009_multi_finding_batch.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["finding_count"] == 3
    assert actuals["by_outcome"]["recommended_only"] == 3


@pytest.mark.asyncio
async def test_mixed_action_classes(tmp_path: Path) -> None:
    case = _load_case("010_mixed_action_classes.yaml")
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert passed, reason
    assert actuals["action_types_distinct"] == 3


# ---------------------------- failure-mode tests --------------------------


@pytest.mark.asyncio
async def test_failure_reason_when_finding_count_mismatches(tmp_path: Path) -> None:
    """If `expected.finding_count` is wrong, the runner reports the mismatch."""
    case = EvalCase(
        case_id="finding_count_mismatch",
        description="finding_count mismatch — bogus expected to verify failure path",
        fixture={
            "mode": "recommend",
            "authorization": {
                "mode_recommend_authorized": True,
                "authorized_actions": ["remediation_k8s_patch_runAsNonRoot"],
            },
            "findings": [_finding_dict()],
        },
        expected={"finding_count": 99},
    )
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert not passed
    assert reason is not None and "finding_count expected 99" in reason
    assert actuals["finding_count"] == 1


@pytest.mark.asyncio
async def test_failure_when_unexpected_exception(tmp_path: Path) -> None:
    """Unhandled AuthorizationError without `raises:` clause = failure with reason."""
    case = EvalCase(
        case_id="unexpected_raise",
        description="unauthorised dry_run without raises clause",
        fixture={
            "mode": "dry_run",
            "authorization": {"mode_recommend_authorized": True},
            "findings": [],
        },
        expected={"finding_count": 0},
    )
    runner = RemediationEvalRunner()
    passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path)
    assert not passed
    assert reason is not None and "unexpected AuthorizationError" in reason
    assert actuals["raised"] == "AuthorizationError"


@pytest.mark.asyncio
async def test_raises_clause_but_no_exception(tmp_path: Path) -> None:
    """`raises: AuthorizationError` set but run completes normally = failure."""
    case = EvalCase(
        case_id="raises_but_ok",
        description="raises set but the run succeeds",
        fixture={
            "mode": "recommend",
            "authorization": {"mode_recommend_authorized": True},
            "findings": [],
        },
        expected={"raises": "AuthorizationError"},
    )
    runner = RemediationEvalRunner()
    passed, reason, _, _ = await runner.run(case, workspace=tmp_path)
    assert not passed
    assert reason is not None and "expected AuthorizationError" in reason


@pytest.mark.asyncio
async def test_audit_log_path_is_returned(tmp_path: Path) -> None:
    """Every successful run should surface the audit.jsonl path for the harness."""
    case = _load_case("001_clean.yaml")
    runner = RemediationEvalRunner()
    _, _, _, audit_path = await runner.run(case, workspace=tmp_path)
    assert audit_path is not None
    assert audit_path.name == "audit.jsonl"
    assert audit_path.exists()


# ---------------------------- helpers -------------------------------------


def _load_case(filename: str) -> EvalCase:
    return load_case_file(CASES_DIR / filename)


def _finding_dict() -> dict[str, object]:
    return {
        "rule_id": "run-as-root",
        "rule_title": "Container running as root",
        "severity": "high",
        "workload_kind": "Deployment",
        "workload_name": "frontend",
        "namespace": "production",
        "container_name": "nginx",
        "manifest_path": "cluster:///production/Deployment/frontend",
        "detected_at": "2026-05-16T12:00:00Z",
    }
