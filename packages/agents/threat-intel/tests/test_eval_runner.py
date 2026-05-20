"""Tests — D.8 ``ThreatIntelEvalRunner`` (Task 14).

Loads every YAML case in the package's ``eval/cases/`` directory and
runs it through the runner. Mirrors D.4's eval-suite test shape:

  - Each case loads, runs, and passes.
  - The 10-case acceptance gate is enforced (matches the plan's
    "10 YAML cases" commitment).
  - All 4 happy-path finding-types appear in at least one fixture
    expected-counts block.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from eval_framework.cases import EvalCase, load_cases
from threat_intel.eval_runner import ThreatIntelEvalRunner


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
    # Cases are sorted by filename, so the numeric prefixes should be 001..010.
    for i, cid in enumerate(ids, start=1):
        assert cid.startswith(f"{i:03d}_"), f"case {i} has unexpected id {cid!r}"


def test_runner_agent_name() -> None:
    runner = ThreatIntelEvalRunner()
    assert runner.agent_name == "threat_intel"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", load_cases(_cases_dir()), ids=lambda c: c.case_id if isinstance(c, EvalCase) else str(c)
)
async def test_eval_case_passes(case: EvalCase, tmp_path: Path) -> None:
    """Every shipped YAML case must pass the runner."""
    runner = ThreatIntelEvalRunner()
    passed, reason, actuals, _audit = await runner.run(case, workspace=tmp_path)
    assert passed, (
        f"{case.case_id} failed: {reason}\n  expected: {dict(case.expected)}\n  actuals:  {actuals}"
    )


def test_all_four_finding_types_covered_across_suite() -> None:
    """Every ThreatIntelFindingType should appear in at least one
    eval case's expected by_finding_type bucket -- including the
    `attack_technique_observed` bucket which v0.1 doesn't actively
    emit (the case asserts 0 to document the wire shape)."""
    cases = load_cases(_cases_dir())
    seen: set[str] = set()
    for case in cases:
        by_type = case.expected.get("by_finding_type") or {}
        for ft_name in by_type:
            seen.add(str(ft_name))
    expected = {
        "threat_intel_cve_in_kev_catalog",
        "threat_intel_ioc_match_network",
        "threat_intel_ioc_match_runtime",
        "threat_intel_attack_technique_observed",
    }
    missing = expected - seen
    assert not missing, f"finding-types missing from eval expectations: {missing}"


def test_severity_canonicalisation_case_present() -> None:
    """Case 009 verifies the scorer's CRITICAL re-stamp is the canonical
    source of truth (Meta-Harness + D.7 dispatch on this)."""
    cases = load_cases(_cases_dir())
    ids = {c.case_id for c in cases}
    assert "009_scorer_canonicalises_kev_to_critical" in ids


def test_partial_workspace_case_present() -> None:
    """Case 008 is the WI-5 regression probe -- a malformed sibling
    findings.json must not poison other correlators."""
    cases = load_cases(_cases_dir())
    ids = {c.case_id for c in cases}
    assert "008_partial_workspace_presence" in ids
