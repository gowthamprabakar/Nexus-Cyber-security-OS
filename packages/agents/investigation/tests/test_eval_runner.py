"""Tests for `investigation.eval_runner.InvestigationEvalRunner` (D.7 Task 14).

Production contract:

- Conforms to `eval_framework.runner.EvalRunner` Protocol.
- `agent_name == "investigation"` matches the pyproject entry-point.
- Registered via `nexus_eval_runners` entry-point.
- Interprets the F.6/F.5-style YAML fixture schema from Task 13.
- All 10 shipped YAML cases pass — the **10/10 acceptance gate**.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner
from investigation.eval_runner import InvestigationEvalRunner

_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def _load_case(case_file: Path) -> EvalCase:
    raw = yaml.safe_load(case_file.read_text())
    return EvalCase(
        case_id=raw["case_id"],
        description=raw.get("description", ""),
        fixture=raw.get("fixture") or {},
        expected=raw.get("expected") or {},
    )


# ---------------------------- protocol + name ---------------------------


def test_investigation_eval_runner_is_an_eval_runner() -> None:
    runner = InvestigationEvalRunner()
    assert isinstance(runner, EvalRunner)


def test_runner_agent_name_matches_entry_point() -> None:
    assert InvestigationEvalRunner().agent_name == "investigation"


def test_entry_point_resolves_to_runner() -> None:
    from importlib.metadata import entry_points

    eps = entry_points(group="nexus_eval_runners")
    ep = next(e for e in eps if e.name == "investigation")
    assert ep.load() is InvestigationEvalRunner


# ---------------------------- per-case execution ------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_filename",
    [
        "001_empty_corpus.yaml",
        "002_audit_only_no_hypotheses.yaml",
        "003_single_finding_fallback.yaml",
        "004_cross_agent_merge.yaml",
        "005_ioc_extraction.yaml",
        "006_mitre_attribution.yaml",
        "007_llm_hypothesis_validated.yaml",
        "008_llm_hallucination_dropped.yaml",
        "009_time_window_filter.yaml",
        "010_containment_plan_per_class.yaml",
    ],
)
async def test_each_shipped_case_passes(tmp_path: Path, case_filename: str) -> None:
    case = _load_case(_CASES_DIR / case_filename)
    passed, reason, _, _ = await InvestigationEvalRunner().run(
        case, workspace=tmp_path / case.case_id
    )
    assert passed, f"{case.case_id}: {reason}"


# ---------------------------- full 10/10 acceptance ---------------------


@pytest.mark.asyncio
async def test_all_10_shipped_cases_pass(tmp_path: Path) -> None:
    case_files = sorted(_CASES_DIR.glob("*.yaml"))
    assert len(case_files) == 10, f"D.7 ships exactly 10 eval cases; got {len(case_files)}"

    runner = InvestigationEvalRunner()
    failures: list[str] = []
    for cf in case_files:
        case = _load_case(cf)
        passed, reason, _, _ = await runner.run(case, workspace=tmp_path / case.case_id)
        if not passed:
            failures.append(f"{case.case_id}: {reason}")
    assert not failures, "\n".join(failures)


# ---------------------------- audit log emission ------------------------


@pytest.mark.asyncio
async def test_runner_emits_audit_log_path(tmp_path: Path) -> None:
    case = _load_case(_CASES_DIR / "003_single_finding_fallback.yaml")
    _, _, _, audit_log_path = await InvestigationEvalRunner().run(case, workspace=tmp_path)
    assert audit_log_path is not None
    assert audit_log_path.is_file()
