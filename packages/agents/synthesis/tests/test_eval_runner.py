"""Tests — ``synthesis.eval_runner`` + 10 bundled YAML cases (Task 11).

Acceptance gate: **10/10 cases pass**. Each case is loaded, run
through the SynthesisEvalRunner against a tmp_path workspace, and
asserted to pass.

Plus:
- Entry-point registration (``nexus_eval_runners`` exposes the
  ``synthesis`` runner).
- Runner contract (RunOutcome shape).
- Eval-framework Protocol conformance.
"""

from __future__ import annotations

from importlib import metadata
from pathlib import Path

import pytest
from eval_framework.cases import EvalCase, load_case_file
from eval_framework.runner import EvalRunner
from synthesis.eval_runner import SynthesisEvalRunner

_CASES_DIR = Path(__file__).parent.parent / "eval" / "cases"


def _all_case_files() -> list[Path]:
    return sorted(_CASES_DIR.glob("*.yaml"))


# ---------------------------------------------------------------------------
# Runner registration + Protocol shape
# ---------------------------------------------------------------------------


def test_runner_satisfies_eval_runner_protocol() -> None:
    runner = SynthesisEvalRunner()
    assert isinstance(runner, EvalRunner)
    assert runner.agent_name == "synthesis"


def test_runner_registered_via_entry_point() -> None:
    """Task 1 declared the entry point in pyproject.toml; check it loads."""
    eps = metadata.entry_points(group="nexus_eval_runners")
    names = [ep.name for ep in eps]
    assert "synthesis" in names
    # Load and verify it returns the same class.
    entry = next(ep for ep in eps if ep.name == "synthesis")
    cls = entry.load()
    assert cls is SynthesisEvalRunner


# ---------------------------------------------------------------------------
# All 10 cases load
# ---------------------------------------------------------------------------


def test_ten_case_files_present() -> None:
    cases = _all_case_files()
    assert len(cases) == 10, f"expected 10 eval cases, found {len(cases)}: {cases}"


def test_all_case_files_parse_as_eval_cases() -> None:
    """Every YAML file in eval/cases/ must validate against EvalCase."""
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
    runner = SynthesisEvalRunner()

    passed, failure_reason, actuals, _audit_log = await runner.run(case, workspace=tmp_path)

    assert passed, f"{case.case_id} failed: {failure_reason} (actuals={actuals})"


# ---------------------------------------------------------------------------
# Runner contract — RunOutcome shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_outcome_actuals_shape(tmp_path: Path) -> None:
    case = load_case_file(_CASES_DIR / "01-clean-no-findings.yaml")
    runner = SynthesisEvalRunner()

    passed, failure_reason, actuals, _audit_log = await runner.run(case, workspace=tmp_path)

    assert passed
    assert failure_reason is None
    # Actuals dict carries the keys the framework can inspect.
    assert "section_count" in actuals
    assert "review_retries" in actuals
    assert "cited_finding_count" in actuals


@pytest.mark.asyncio
async def test_run_fails_with_reason_on_section_count_mismatch(tmp_path: Path) -> None:
    """Synthetic case: change expected section_count -> failure reason
    is surfaced cleanly."""
    case = load_case_file(_CASES_DIR / "01-clean-no-findings.yaml")
    bad_case = case.model_copy(update={"expected": {**case.expected, "section_count": 99}})
    runner = SynthesisEvalRunner()

    passed, failure_reason, _actuals, _audit_log = await runner.run(bad_case, workspace=tmp_path)

    assert not passed
    assert failure_reason is not None
    assert "section_count" in failure_reason


@pytest.mark.asyncio
async def test_q6_case_excludes_leaked_substring(tmp_path: Path) -> None:
    """The Q6 case must drop the leaked SSN from narrative.md. This is
    the explicit WI-2 regression probe."""
    case = load_case_file(_CASES_DIR / "07-classifier-substring-rejection.yaml")
    runner = SynthesisEvalRunner()

    passed, failure_reason, actuals, _audit_log = await runner.run(case, workspace=tmp_path)

    assert passed, f"Q6 case failed: {failure_reason}"
    assert actuals["review_retries"] == 1


@pytest.mark.asyncio
async def test_q6_invariant_case_excludes_secret_leak(tmp_path: Path) -> None:
    """The context-bundle invariant case: even if the raw F.3 finding
    carries a matched-text field, neither the bundle nor the rendered
    narrative may leak it."""
    case = load_case_file(_CASES_DIR / "10-context-bundle-q6-invariant.yaml")
    runner = SynthesisEvalRunner()

    passed, failure_reason, _actuals, _audit_log = await runner.run(case, workspace=tmp_path)

    assert passed, f"Q6 invariant case failed: {failure_reason}"
