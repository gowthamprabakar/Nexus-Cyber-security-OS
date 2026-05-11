"""Tests for `runtime_threat.eval_runner.RuntimeThreatEvalRunner`.

Two surfaces tested:

1. Protocol satisfaction + happy / mismatch shape on synthetic cases.
2. The 10/10 acceptance gate against the YAMLs in `eval/cases/`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner
from runtime_threat.eval_runner import RuntimeThreatEvalRunner

CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def _load_case(path: Path) -> EvalCase:
    raw = yaml.safe_load(path.read_text())
    return EvalCase.model_validate(raw)


# ---------------------------- protocol satisfaction ----------------------


def test_runner_satisfies_protocol() -> None:
    runner = RuntimeThreatEvalRunner()
    assert isinstance(runner, EvalRunner)
    assert runner.agent_name == "runtime_threat"


# ---------------------------- happy / mismatch synthetic cases ----------


@pytest.mark.asyncio
async def test_run_empty_case_yields_pass(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_empty",
        description="all feeds empty",
        fixture={"falco_alerts": [], "tracee_alerts": [], "osquery_rows": []},
        expected={"finding_count": 0},
    )
    passed, reason, actuals, audit = await RuntimeThreatEvalRunner().run(case, workspace=tmp_path)
    assert passed is True
    assert reason is None
    assert actuals["finding_count"] == 0
    assert audit is not None and audit.is_file()


@pytest.mark.asyncio
async def test_run_finding_count_mismatch_returns_failure_reason(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_count_mismatch",
        description="empty but expects one finding",
        fixture={"falco_alerts": [], "tracee_alerts": [], "osquery_rows": []},
        expected={"finding_count": 1},
    )
    passed, reason, _, _ = await RuntimeThreatEvalRunner().run(case, workspace=tmp_path)
    assert passed is False
    assert reason is not None
    assert "finding_count" in reason


@pytest.mark.asyncio
async def test_run_severity_mismatch_returns_failure_reason(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_sev_mismatch",
        description="Falco alert but bogus expected severity count",
        fixture={
            "falco_alerts": [
                {
                    "time": "2026-05-11T12:00:00Z",
                    "rule": "Terminal shell in container",
                    "priority": "Critical",
                    "output": "shell spawned",
                    "output_fields": {"container.id": "abc"},
                    "tags": ["container", "shell", "process"],
                }
            ],
            "tracee_alerts": [],
            "osquery_rows": [],
        },
        expected={"by_severity": {"critical": 99}},
    )
    passed, reason, _, _ = await RuntimeThreatEvalRunner().run(case, workspace=tmp_path)
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
    case = _load_case(case_path)
    passed, reason, actuals, _ = await RuntimeThreatEvalRunner().run(case, workspace=tmp_path)
    assert passed, f"case {case.case_id} failed: {reason}; actuals={actuals}"
