"""Tests for the AI-SPM eval runner (D.11 PR6) — runs the golden cases."""

from __future__ import annotations

from pathlib import Path

import pytest
from aispm.eval_runner import AISPMEvalRunner
from eval_framework.cases import load_cases

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_agent_name() -> None:
    assert AISPMEvalRunner().agent_name == "aispm"


def test_runner_satisfies_protocol() -> None:
    from eval_framework.runner import EvalRunner

    assert isinstance(AISPMEvalRunner(), EvalRunner)


@pytest.mark.asyncio
async def test_all_golden_cases_pass(tmp_path: Path) -> None:
    runner = AISPMEvalRunner()
    cases = load_cases(_CASES_DIR)
    assert len(cases) >= 4  # clean AWS + AWS findings + azure/vertex + prompt-injection
    for i, case in enumerate(cases):
        passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path / f"c{i}")
        assert passed, f"{case.case_id}: {reason} (actuals={actuals})"
