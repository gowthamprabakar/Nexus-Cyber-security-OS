"""Tests — `meta_harness.eval_runner` + the 15 runner-compatible YAML eval cases (Task 12).

18 tests covering:

1.  ``MetaHarnessEvalRunner.agent_name == "meta_harness"``.
2.  Runner satisfies the ``EvalRunner`` Protocol.
3.  Entry point ``meta_harness`` registered under
    ``nexus_eval_runners`` (verifies pyproject wiring).
4.  All 20 bundled YAML cases parse cleanly via ``load_cases``
    (15 runner-compatible + 5 G1 effectiveness-scoring).
5.  Case ids match the file names.
6.  Each case ships a non-empty fixture or expected block.

7-16. Each of the 10 original bundled cases passes when executed via
      ``run_suite``: clean_batch / one_agent_regression /
      multi_agent_regression / ab_comparison_clean /
      ab_comparison_divergent / single_agent_failed_eval_tolerated /
      never_prior_scorecard / watch_list_population /
      introspection_shape / kg_upsert_skipped_when_none.

17.   The 5 v0.2 skill-lifecycle cases (11-15) pass via ``run_suite``.

18.   The 15 runner-compatible cases (01-15) pass the full suite run.
      G1 cases (16-20) are tested separately via ``test_g1_eval_cases.py``.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path

import pytest
from eval_framework.cases import load_case_file, load_cases
from eval_framework.runner import EvalRunner
from eval_framework.suite import run_suite
from meta_harness.eval_runner import MetaHarnessEvalRunner

_CASES_DIR = Path(__file__).parent.parent / "eval" / "cases"


def test_runner_agent_name() -> None:
    runner = MetaHarnessEvalRunner()
    assert runner.agent_name == "meta_harness"


def test_runner_satisfies_eval_runner_protocol() -> None:
    assert isinstance(MetaHarnessEvalRunner(), EvalRunner)


def test_entry_point_registered() -> None:
    eps = importlib.metadata.entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in eps}
    assert "meta_harness" in names


_G1_CASE_ID_PREFIXES = ("16_", "17_", "18_", "19_", "20_")


def _is_g1_case(case_id: str) -> bool:
    return any(case_id.startswith(p) for p in _G1_CASE_ID_PREFIXES)


def test_all_cases_load_cleanly() -> None:
    cases = load_cases(_CASES_DIR)
    assert len(cases) == 20  # 15 runner-compatible + 5 G1


def test_case_ids_match_filenames() -> None:
    for path in sorted(_CASES_DIR.glob("*.yaml")):
        case = load_case_file(path)
        # case_id should be the file's stem.
        assert case.case_id == path.stem, (
            f"case_id mismatch: {path.name} has case_id={case.case_id!r}"
        )


def test_each_case_has_non_empty_fixture_or_expected() -> None:
    for case in load_cases(_CASES_DIR):
        assert case.fixture or case.expected, (
            f"case {case.case_id} ships an empty fixture AND empty expected"
        )


@pytest.mark.parametrize(
    "case_filename",
    [
        "01_clean_batch.yaml",
        "02_one_agent_regression.yaml",
        "03_multi_agent_regression.yaml",
        "04_ab_comparison_clean.yaml",
        "05_ab_comparison_divergent.yaml",
        "06_single_agent_failed_eval_tolerated.yaml",
        "07_never_prior_scorecard.yaml",
        "08_watch_list_population.yaml",
        "09_introspection_shape.yaml",
        "10_kg_upsert_skipped_when_none.yaml",
    ],
)
@pytest.mark.asyncio
async def test_individual_case_passes_v0_1(case_filename: str, tmp_path: Path) -> None:
    case = load_case_file(_CASES_DIR / case_filename)
    runner = MetaHarnessEvalRunner()
    workspace = tmp_path / case.case_id
    workspace.mkdir(parents=True, exist_ok=True)
    passed, failure_reason, _actuals, _log = await runner.run(case, workspace=workspace)
    assert passed, f"case {case.case_id} failed: {failure_reason}"


@pytest.mark.parametrize(
    "case_filename",
    [
        "11_skill_lifecycle_skipped.yaml",
        "12_skill_eval_gate_fail_reject.yaml",
        "13_skill_auto_deploy.yaml",
        "14_skill_first_of_class_pending.yaml",
        "15_skill_no_trigger.yaml",
    ],
)
@pytest.mark.asyncio
async def test_individual_case_passes_v0_2(case_filename: str, tmp_path: Path) -> None:
    case = load_case_file(_CASES_DIR / case_filename)
    runner = MetaHarnessEvalRunner()
    workspace = tmp_path / case.case_id
    workspace.mkdir(parents=True, exist_ok=True)
    passed, failure_reason, _actuals, _log = await runner.run(case, workspace=workspace)
    assert passed, f"case {case.case_id} failed: {failure_reason}"


@pytest.mark.asyncio
async def test_full_suite_runner_compatible_cases_pass(tmp_path: Path) -> None:
    """End-to-end via run_suite — only runner-compatible cases (01-15).
    G1 cases (16-20) are tested separately via ``test_g1_eval_cases.py``."""
    cases = [c for c in load_cases(_CASES_DIR) if not _is_g1_case(c.case_id)]
    assert len(cases) == 15, f"expected 15 runner-compatible cases, got {len(cases)}"
    result = await run_suite(cases, MetaHarnessEvalRunner(), workspace_root=tmp_path)
    passed_count = sum(1 for r in result.cases if r.passed)
    failures = [(r.case_id, r.failure_reason) for r in result.cases if not r.passed]
    assert passed_count == 15, f"expected 15/15; failures: {failures}"
