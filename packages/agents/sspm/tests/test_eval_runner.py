"""Tests for the SSPM eval runner (D.10 PR6) — runs the golden cases."""

from __future__ import annotations

from pathlib import Path

import pytest
from eval_framework.cases import load_cases
from sspm.eval_runner import SSPMEvalRunner

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_agent_name() -> None:
    assert SSPMEvalRunner().agent_name == "sspm"


def test_runner_satisfies_protocol() -> None:
    from eval_framework.runner import EvalRunner

    assert isinstance(SSPMEvalRunner(), EvalRunner)


@pytest.mark.asyncio
async def test_all_golden_cases_pass(tmp_path: Path) -> None:
    runner = SSPMEvalRunner()
    cases = load_cases(_CASES_DIR)
    assert len(cases) >= 4  # github clean + github/m365/slack findings
    for i, case in enumerate(cases):
        passed, reason, actuals, _ = await runner.run(case, workspace=tmp_path / f"c{i}")
        assert passed, f"{case.case_id}: {reason} (actuals={actuals})"
