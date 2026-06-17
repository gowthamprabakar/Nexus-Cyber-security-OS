"""Tests — D.9 ``ComplianceEvalRunner`` (Task 13).

Loads every YAML case in the package's ``eval/cases/`` directory and
runs it through the runner. Mirrors D.8's eval-suite test shape:

  - Each case loads, runs, and passes.
  - The 10-case acceptance gate is enforced (matches the plan's
    "10 YAML cases" commitment).
  - WI-2 case (`008_cis_attribution_in_output`) is explicitly
    present.
  - Partial-workspace case (`005_partial_workspace_presence`) is
    explicitly present.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from compliance.eval_runner import ComplianceEvalRunner
from eval_framework.cases import EvalCase, load_cases


def _cases_dir() -> Path:
    """Resolve the package's eval cases directory."""
    return Path(__file__).resolve().parents[1] / "eval" / "cases"


def test_eval_cases_directory_exists() -> None:
    assert _cases_dir().is_dir()


def test_exactly_ten_eval_cases_shipped() -> None:
    cases = load_cases(_cases_dir())
    assert len(cases) == 10, f"expected 10 eval cases, got {len(cases)}"


def test_case_ids_are_unique_and_sequential() -> None:
    cases = load_cases(_cases_dir())
    ids = [c.case_id for c in cases]
    assert len(ids) == len(set(ids))
    # Cases sorted by filename -> numeric prefixes 001..010.
    for i, cid in enumerate(ids, start=1):
        assert cid.startswith(f"{i:03d}_"), f"case {i} has unexpected id {cid!r}"


def test_runner_agent_name() -> None:
    runner = ComplianceEvalRunner()
    assert runner.agent_name == "compliance"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    load_cases(_cases_dir()),
    ids=lambda c: c.case_id if isinstance(c, EvalCase) else str(c),
)
async def test_eval_case_passes(case: EvalCase, tmp_path: Path) -> None:
    """Every shipped YAML case must pass the runner."""
    runner = ComplianceEvalRunner()
    passed, reason, actuals, _audit = await runner.run(case, workspace=tmp_path)
    assert passed, (
        f"{case.case_id} failed: {reason}\n  expected: {dict(case.expected)}\n  actuals:  {actuals}"
    )


def test_wi2_attribution_case_present() -> None:
    """Case 008 is the WI-2 regression probe — CIS Benchmarks®
    attribution must appear in report.md."""
    cases = load_cases(_cases_dir())
    ids = {c.case_id for c in cases}
    assert "008_cis_attribution_in_output" in ids


def test_partial_workspace_case_present() -> None:
    """Case 005 is the F.3-malformed regression probe — a malformed
    sibling findings.json must not poison the D.5 correlator."""
    cases = load_cases(_cases_dir())
    ids = {c.case_id for c in cases}
    assert "005_partial_workspace_presence" in ids


def test_multi_source_rollup_case_present() -> None:
    """Case 003 validates the cross-source aggregation — both F.3 and
    D.5 contribute to the same CIS control."""
    cases = load_cases(_cases_dir())
    ids = {c.case_id for c in cases}
    assert "003_multi_source_rollup" in ids


def test_severity_canonicalization_case_present() -> None:
    """Case 009 verifies the canonical scorer table via a custom 2-
    control library."""
    cases = load_cases(_cases_dir())
    ids = {c.case_id for c in cases}
    assert "009_severity_canonicalization" in ids


def test_every_case_has_finding_count_expectation() -> None:
    """Defensive: every case must assert a `finding_count` so the
    eval gate has a concrete number to enforce."""
    cases = load_cases(_cases_dir())
    missing = [c.case_id for c in cases if "finding_count" not in c.expected]
    assert not missing, f"cases missing finding_count expectation: {missing}"
