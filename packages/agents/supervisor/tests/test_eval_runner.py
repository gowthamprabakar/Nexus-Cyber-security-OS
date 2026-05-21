"""Tests — `supervisor.eval_runner` + the 15 bundled YAML cases (Task 12).

18 tests covering:

1.  ``SupervisorEvalRunner.agent_name == "supervisor"``.
2.  Runner satisfies the ``EvalRunner`` Protocol.
3.  Entry point ``supervisor`` registered under
    ``nexus_eval_runners`` — the 17th and final v0.1 entry.
4.  All 15 bundled YAML cases parse cleanly via ``load_cases``.
5.  Case ids match the file names.
6.  Each case ships a non-empty fixture + expected block.

7-16. Each of the 10 happy-path-per-specialist cases passes via
      direct ``runner.run(...)``.

17-21. Each of the 5 edge-case cases passes via direct
       ``runner.run(...)``.

22.   ``supervisor eval`` produces 15/15 via the eval-framework's
      ``run_suite`` against the registered runner.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path

import pytest
from eval_framework.cases import load_case_file, load_cases
from eval_framework.runner import EvalRunner
from eval_framework.suite import run_suite
from supervisor.eval_runner import SupervisorEvalRunner

_CASES_DIR = Path(__file__).parent.parent / "eval" / "cases"


def test_runner_agent_name() -> None:
    assert SupervisorEvalRunner().agent_name == "supervisor"


def test_runner_satisfies_eval_runner_protocol() -> None:
    assert isinstance(SupervisorEvalRunner(), EvalRunner)


def test_entry_point_registered() -> None:
    eps = importlib.metadata.entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in eps}
    assert "supervisor" in names


def test_all_fifteen_cases_load_cleanly() -> None:
    cases = load_cases(_CASES_DIR)
    assert len(cases) == 15


def test_case_ids_match_filenames() -> None:
    for path in sorted(_CASES_DIR.glob("*.yaml")):
        case = load_case_file(path)
        assert case.case_id == path.stem, (
            f"case_id mismatch: {path.name} has case_id={case.case_id!r}"
        )


def test_each_case_has_non_empty_fixture_and_expected() -> None:
    for case in load_cases(_CASES_DIR):
        assert case.fixture, f"case {case.case_id} has empty fixture"
        assert case.expected, f"case {case.case_id} has empty expected"


@pytest.mark.parametrize(
    "case_filename",
    [
        "01_route_cloud_posture.yaml",
        "02_route_vulnerability.yaml",
        "03_route_identity.yaml",
        "04_route_runtime_threat.yaml",
        "05_route_audit.yaml",
        "06_route_investigation.yaml",
        "07_route_network_threat.yaml",
        "08_route_multi_cloud_posture.yaml",
        "09_route_k8s_posture.yaml",
        "10_route_remediation.yaml",
        "11_no_target_agent_pattern_match.yaml",
        "12_ambiguous_routing.yaml",
        "13_forbidden_target_agent.yaml",
        "14_over_capacity_parallel_tasks.yaml",
        "15_escalation_on_budget_exceeded.yaml",
    ],
)
@pytest.mark.asyncio
async def test_individual_case_passes(case_filename: str, tmp_path: Path) -> None:
    case = load_case_file(_CASES_DIR / case_filename)
    runner = SupervisorEvalRunner()
    workspace = tmp_path / case.case_id
    workspace.mkdir(parents=True, exist_ok=True)
    passed, failure_reason, _actuals, _log = await runner.run(case, workspace=workspace)
    assert passed, f"case {case.case_id} failed: {failure_reason}"


@pytest.mark.asyncio
async def test_full_suite_15_of_15_via_run_suite(tmp_path: Path) -> None:
    cases = load_cases(_CASES_DIR)
    result = await run_suite(cases, SupervisorEvalRunner(), workspace_root=tmp_path)
    passed_count = sum(1 for r in result.cases if r.passed)
    failures = [(r.case_id, r.failure_reason) for r in result.cases if not r.passed]
    assert passed_count == 15, f"expected 15/15; failures: {failures}"
