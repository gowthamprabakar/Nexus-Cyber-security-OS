"""Tests for the minimal local eval runner."""

from __future__ import annotations

from pathlib import Path

import pytest
from cloud_posture._eval_local import (
    EvalCase,
    EvalResult,
    load_cases,
    run_case,
)

# ---------------------------- load_cases -----------------------------------


def test_load_cases_reads_yaml(tmp_path: Path) -> None:
    case_file = tmp_path / "001_x.yaml"
    case_file.write_text(
        """
case_id: 001_x
description: smoke
fixture:
  prowler_findings: []
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 0
  has_severity:
    critical: 0
    high: 0
"""
    )
    cases = load_cases(tmp_path)
    assert len(cases) == 1
    assert cases[0].case_id == "001_x"
    assert cases[0].description == "smoke"
    assert cases[0].expected["finding_count"] == 0


def test_load_cases_sorts_lexicographically(tmp_path: Path) -> None:
    """Ordering must be deterministic regardless of fs ordering."""
    for name in ("002_b.yaml", "001_a.yaml", "003_c.yaml"):
        (tmp_path / name).write_text(
            f"""
case_id: {name.replace(".yaml", "")}
description: x
fixture:
  prowler_findings: []
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 0
"""
        )
    cases = load_cases(tmp_path)
    assert [c.case_id for c in cases] == ["001_a", "002_b", "003_c"]


# ---------------------------- run_case --------------------------------------


def test_run_case_passes_when_empty_fixture_matches_zero_findings() -> None:
    case = EvalCase(
        case_id="t_empty",
        description="empty",
        fixture={
            "prowler_findings": [],
            "iam_users_without_mfa": [],
            "iam_admin_policies": [],
        },
        expected={
            "finding_count": 0,
            "has_severity": {"critical": 0, "high": 0},
        },
    )
    result = run_case(case)
    assert isinstance(result, EvalResult)
    assert result.passed is True, result.failure_reason
    assert result.actual_counts["high"] == 0


def test_run_case_fails_on_count_mismatch() -> None:
    case = EvalCase(
        case_id="t_count_mismatch",
        description="bob without mfa expected 0",
        fixture={
            "prowler_findings": [],
            "iam_users_without_mfa": ["bob"],
            "iam_admin_policies": [],
        },
        expected={"finding_count": 0, "has_severity": {"high": 0}},
    )
    result = run_case(case)
    assert result.passed is False
    assert "finding_count" in (result.failure_reason or "")
    assert result.actual_counts["high"] == 1


def test_run_case_passes_when_severity_matches() -> None:
    case = EvalCase(
        case_id="t_sev_high",
        description="bob without mfa → one high",
        fixture={
            "prowler_findings": [],
            "iam_users_without_mfa": ["bob"],
            "iam_admin_policies": [],
        },
        expected={"finding_count": 1, "has_severity": {"high": 1, "critical": 0}},
    )
    result = run_case(case)
    assert result.passed is True, result.failure_reason


def test_run_case_fails_on_severity_mismatch() -> None:
    """Same fixture as above but expected critical instead of high."""
    case = EvalCase(
        case_id="t_sev_mismatch",
        description="bob without mfa expected critical",
        fixture={
            "prowler_findings": [],
            "iam_users_without_mfa": ["bob"],
            "iam_admin_policies": [],
        },
        expected={"finding_count": 1, "has_severity": {"critical": 1}},
    )
    result = run_case(case)
    assert result.passed is False
    assert "critical" in (result.failure_reason or "")


# ---------------------------- end-to-end on shipped cases --------------------


_SHIPPED_CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


@pytest.mark.skipif(
    not _SHIPPED_CASES_DIR.is_dir(),
    reason=f"shipped eval cases not yet present at {_SHIPPED_CASES_DIR}",
)
def test_all_shipped_cases_pass() -> None:
    """Every YAML case under eval/cases/ must produce a passing EvalResult.

    This is the regression-guard for both the eval runner and the agent
    driver — if any case fails, either the fixture is wrong or the agent's
    finding-shape contract drifted.
    """
    cases = load_cases(_SHIPPED_CASES_DIR)
    assert len(cases) >= 10, f"expected ≥ 10 shipped cases, found {len(cases)}"

    failures = []
    for case in cases:
        result = run_case(case)
        if not result.passed:
            failures.append(
                f"{result.case_id}: {result.failure_reason} (actual_counts={result.actual_counts})"
            )
    assert not failures, "\n".join(failures)
