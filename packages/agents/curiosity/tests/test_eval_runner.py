"""Tests — `curiosity.eval_runner` + 10 bundled YAML cases (Task 12).

Acceptance gate: 10/10 cases pass. Each case is loaded, run
through the CuriosityEvalRunner against a tmp_path workspace, and
asserted to pass.

Plus:
- Entry-point registration (`nexus_eval_runners.curiosity`).
- Runner Protocol conformance.
- RunOutcome shape probe.
- Failure-reason surfacing on synthetic mismatch.
- WI-2 explicit assertion: Q6 case excludes leaked substring.
"""

from __future__ import annotations

from importlib import metadata
from pathlib import Path

import pytest
from curiosity.eval_runner import CuriosityEvalRunner
from eval_framework.cases import EvalCase, load_case_file
from eval_framework.runner import EvalRunner

_CASES_DIR = Path(__file__).parent.parent / "eval" / "cases"


def _all_case_files() -> list[Path]:
    return sorted(_CASES_DIR.glob("*.yaml"))


# ---------------------------------------------------------------------------
# Runner registration + Protocol shape
# ---------------------------------------------------------------------------


def test_runner_satisfies_eval_runner_protocol() -> None:
    runner = CuriosityEvalRunner()
    assert isinstance(runner, EvalRunner)
    assert runner.agent_name == "curiosity"


def test_runner_registered_via_entry_point() -> None:
    """Task 1 declared the entry point in pyproject.toml; check it loads."""
    eps = metadata.entry_points(group="nexus_eval_runners")
    names = [ep.name for ep in eps]
    assert "curiosity" in names
    entry = next(ep for ep in eps if ep.name == "curiosity")
    cls = entry.load()
    assert cls is CuriosityEvalRunner


# ---------------------------------------------------------------------------
# All 10 cases load
# ---------------------------------------------------------------------------


def test_ten_case_files_present() -> None:
    cases = _all_case_files()
    assert len(cases) == 10, f"expected 10 eval cases, found {len(cases)}: {cases}"


def test_all_case_files_parse_as_eval_cases() -> None:
    for path in _all_case_files():
        case = load_case_file(path)
        assert isinstance(case, EvalCase)
        assert case.case_id
        assert case.description


# ---------------------------------------------------------------------------
# 10/10 acceptance gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_file",
    _all_case_files(),
    ids=lambda p: p.stem,
)
async def test_case_passes(case_file: Path, tmp_path: Path) -> None:
    """Every bundled case must pass."""
    case = load_case_file(case_file)
    runner = CuriosityEvalRunner()

    passed, failure_reason, actuals, _audit_log = await runner.run(case, workspace=tmp_path)

    assert passed, f"{case.case_id} failed: {failure_reason} (actuals={actuals})"


# ---------------------------------------------------------------------------
# Runner contract — RunOutcome shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_outcome_actuals_shape(tmp_path: Path) -> None:
    case = load_case_file(_CASES_DIR / "01-clean-no-gaps.yaml")
    runner = CuriosityEvalRunner()

    passed, failure_reason, actuals, _audit_log = await runner.run(case, workspace=tmp_path)

    assert passed
    assert failure_reason is None
    assert "total_claims" in actuals
    assert "review_retries" in actuals
    assert "total_gaps_addressed" in actuals
    assert "semantic_store_upsert_count" in actuals
    assert "fabric_publish_count" in actuals


@pytest.mark.asyncio
async def test_run_fails_with_reason_on_total_claims_mismatch(tmp_path: Path) -> None:
    """Synthetic case: change expected total_claims -> failure reason
    is surfaced cleanly."""
    case = load_case_file(_CASES_DIR / "01-clean-no-gaps.yaml")
    bad_case = case.model_copy(update={"expected": {**case.expected, "total_claims": 99}})
    runner = CuriosityEvalRunner()

    passed, failure_reason, _actuals, _audit_log = await runner.run(bad_case, workspace=tmp_path)

    assert not passed
    assert failure_reason is not None
    assert "total_claims" in failure_reason


# ---------------------------------------------------------------------------
# WI-2 — Q6 case excludes leaked substring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_q6_case_excludes_leaked_substring(tmp_path: Path) -> None:
    """The Q6 case must drop the leaked SSN from hypotheses.md. This is
    the explicit WI-2 regression probe."""
    case = load_case_file(_CASES_DIR / "05-q6-rejection.yaml")
    runner = CuriosityEvalRunner()

    passed, failure_reason, actuals, _audit_log = await runner.run(case, workspace=tmp_path)

    assert passed, f"Q6 case failed: {failure_reason}"
    assert actuals["review_retries"] == 1


# ---------------------------------------------------------------------------
# Q5 single-tenant case verifies no PERSIST / no PUBLISH
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_q5_single_tenant_case_skips_persist_and_publish(tmp_path: Path) -> None:
    case = load_case_file(_CASES_DIR / "10-kg-upsert-skipped-when-none.yaml")
    runner = CuriosityEvalRunner()

    passed, failure_reason, actuals, _audit_log = await runner.run(case, workspace=tmp_path)

    assert passed, f"Q5 case failed: {failure_reason}"
    assert actuals["semantic_store_upsert_count"] == 0
    assert actuals["fabric_publish_count"] == 0
