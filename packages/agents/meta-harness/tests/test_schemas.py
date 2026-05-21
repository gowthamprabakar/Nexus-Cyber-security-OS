"""Tests — `meta_harness.schemas` (Task 2).

Covers each of the six pydantic types + their invariants:

- ``AgentManifest`` — bounded fields; declared-tool entries cannot
  be empty / over-long.
- ``Scorecard`` — XOR pass_rate / error; passed + failed == total
  when successful.
- ``ScorecardDelta`` — first-run edge (delta=0; prev=None);
  is_comparable property reflects both pass_rates non-None.
- ``ABComparisonCaseDelta`` — minimal: case_id + bool flags.
- ``ABComparison`` — variants must differ; byte_equal flag present;
  pass-rate bounds enforced.
- ``RegressionFlag`` — bounded numeric fields.
- ``MetaHarnessReport`` — top-level holder; counts/properties
  computed correctly; ab_comparison optional.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from meta_harness.schemas import (
    ABComparison,
    ABComparisonCaseDelta,
    AgentManifest,
    MetaHarnessReport,
    RegressionFlag,
    Scorecard,
    ScorecardDelta,
)
from pydantic import ValidationError

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# AgentManifest
# ---------------------------------------------------------------------------


def test_agent_manifest_minimal_valid() -> None:
    manifest = AgentManifest(
        agent_id="cloud_posture",
        persona="A cloud-posture sentinel.",
        declared_tools=("aws_s3_scan", "aws_iam_audit"),
        example_count=3,
        eval_case_count=10,
        nlah_dir="packages/agents/cloud-posture/src/cloud_posture/nlah",
    )
    assert manifest.agent_id == "cloud_posture"
    assert manifest.example_count == 3
    assert manifest.eval_case_count == 10


def test_agent_manifest_rejects_empty_tool_name() -> None:
    with pytest.raises(ValidationError, match="declared_tools entries must be non-empty"):
        AgentManifest(
            agent_id="x",
            declared_tools=("valid_tool", ""),
            example_count=0,
            eval_case_count=0,
            nlah_dir="packages/agents/x/nlah",
        )


def test_agent_manifest_rejects_oversize_tool_name() -> None:
    with pytest.raises(ValidationError, match="declared tool name exceeds"):
        AgentManifest(
            agent_id="x",
            declared_tools=("a" * 200,),
            example_count=0,
            eval_case_count=0,
            nlah_dir="packages/agents/x/nlah",
        )


# ---------------------------------------------------------------------------
# Scorecard
# ---------------------------------------------------------------------------


def test_scorecard_successful_run_valid() -> None:
    sc = Scorecard(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        total_cases=10,
        passed=9,
        failed=1,
        pass_rate=0.9,
        evaluated_at=_NOW,
    )
    assert sc.pass_rate == 0.9
    assert sc.error is None


def test_scorecard_failed_run_valid() -> None:
    sc = Scorecard(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        total_cases=0,
        passed=0,
        failed=0,
        error="ImportError: missing module",
        evaluated_at=_NOW,
    )
    assert sc.pass_rate is None
    assert sc.error == "ImportError: missing module"


def test_scorecard_rejects_both_passrate_and_error() -> None:
    with pytest.raises(ValidationError, match="XOR"):
        Scorecard(
            customer_id="acme",
            run_id="r1",
            agent_id="cloud_posture",
            total_cases=10,
            passed=9,
            failed=1,
            pass_rate=0.9,
            error="should not be here",
            evaluated_at=_NOW,
        )


def test_scorecard_rejects_neither_passrate_nor_error() -> None:
    with pytest.raises(ValidationError, match=r"pass_rate.*or error"):
        Scorecard(
            customer_id="acme",
            run_id="r1",
            agent_id="cloud_posture",
            total_cases=0,
            passed=0,
            failed=0,
            evaluated_at=_NOW,
        )


def test_scorecard_rejects_mismatched_counts_on_success() -> None:
    with pytest.raises(ValidationError, match="must equal"):
        Scorecard(
            customer_id="acme",
            run_id="r1",
            agent_id="cloud_posture",
            total_cases=10,
            passed=8,
            failed=1,  # 8 + 1 != 10
            pass_rate=0.8,
            evaluated_at=_NOW,
        )


# ---------------------------------------------------------------------------
# ScorecardDelta
# ---------------------------------------------------------------------------


def test_scorecard_delta_first_run_valid() -> None:
    d = ScorecardDelta(
        agent_id="cloud_posture",
        previous_pass_rate=None,
        current_pass_rate=0.9,
        delta_pct=0.0,
        is_first_run=True,
    )
    assert d.is_first_run is True
    assert d.is_comparable is False


def test_scorecard_delta_comparable_when_both_present() -> None:
    d = ScorecardDelta(
        agent_id="cloud_posture",
        previous_pass_rate=0.8,
        current_pass_rate=0.7,
        delta_pct=-10.0,
        is_first_run=False,
    )
    assert d.is_comparable is True
    assert d.delta_pct == -10.0


def test_scorecard_delta_first_run_forbids_previous_passrate() -> None:
    with pytest.raises(ValidationError, match="previous_pass_rate=None"):
        ScorecardDelta(
            agent_id="cloud_posture",
            previous_pass_rate=0.8,
            current_pass_rate=0.9,
            delta_pct=10.0,
            is_first_run=True,
        )


def test_scorecard_delta_first_run_forbids_nonzero_delta() -> None:
    with pytest.raises(ValidationError, match=r"delta_pct=0\.0"):
        ScorecardDelta(
            agent_id="cloud_posture",
            previous_pass_rate=None,
            current_pass_rate=0.9,
            delta_pct=5.0,
            is_first_run=True,
        )


# ---------------------------------------------------------------------------
# ABComparisonCaseDelta + ABComparison
# ---------------------------------------------------------------------------


def test_ab_comparison_case_delta_valid() -> None:
    cd = ABComparisonCaseDelta(
        case_id="clean-batch",
        variant_a_passed=True,
        variant_b_passed=True,
        byte_equal=True,
    )
    assert cd.case_id == "clean-batch"


def test_ab_comparison_minimal_valid() -> None:
    ab = ABComparison(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        variant_a_path="packages/agents/cloud-posture/src/cloud_posture/nlah",
        variant_b_path="packages/agents/cloud-posture/src/cloud_posture/nlah/.proposed",
        variant_a_pass_rate=0.9,
        variant_b_pass_rate=0.9,
        byte_equal=True,
        evaluated_at=_NOW,
    )
    assert ab.byte_equal is True
    assert ab.variant_a_path != ab.variant_b_path


def test_ab_comparison_rejects_identical_variants() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        ABComparison(
            customer_id="acme",
            run_id="r1",
            agent_id="cloud_posture",
            variant_a_path="same",
            variant_b_path="same",
            variant_a_pass_rate=0.5,
            variant_b_pass_rate=0.5,
            byte_equal=True,
            evaluated_at=_NOW,
        )


def test_ab_comparison_rejects_out_of_range_pass_rate() -> None:
    with pytest.raises(ValidationError):
        ABComparison(
            customer_id="acme",
            run_id="r1",
            agent_id="cloud_posture",
            variant_a_path="A",
            variant_b_path="B",
            variant_a_pass_rate=1.5,
            variant_b_pass_rate=0.5,
            byte_equal=False,
            evaluated_at=_NOW,
        )


# ---------------------------------------------------------------------------
# RegressionFlag
# ---------------------------------------------------------------------------


def test_regression_flag_valid() -> None:
    f = RegressionFlag(
        agent_id="cloud_posture",
        previous_pass_rate=0.9,
        current_pass_rate=0.7,
        delta_pct=-20.0,
    )
    assert f.delta_pct == -20.0


def test_regression_flag_rejects_out_of_range_delta() -> None:
    with pytest.raises(ValidationError):
        RegressionFlag(
            agent_id="cloud_posture",
            previous_pass_rate=0.9,
            current_pass_rate=0.7,
            delta_pct=-150.0,
        )


# ---------------------------------------------------------------------------
# MetaHarnessReport
# ---------------------------------------------------------------------------


def test_meta_harness_report_minimal_valid() -> None:
    report = MetaHarnessReport(
        customer_id="acme",
        run_id="r1",
        scan_started_at=_NOW,
        scan_completed_at=_NOW,
    )
    assert report.total_agents_evaluated == 0
    assert report.total_regressions == 0
    assert report.successful_runs == 0
    assert report.ab_comparison is None
    assert report.schema_version == "meta_harness.v0.1"


def test_meta_harness_report_counts_reflect_scorecards() -> None:
    success = Scorecard(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        total_cases=10,
        passed=9,
        failed=1,
        pass_rate=0.9,
        evaluated_at=_NOW,
    )
    failure = Scorecard(
        customer_id="acme",
        run_id="r1",
        agent_id="data_security",
        total_cases=0,
        passed=0,
        failed=0,
        error="boom",
        evaluated_at=_NOW,
    )
    report = MetaHarnessReport(
        customer_id="acme",
        run_id="r1",
        scan_started_at=_NOW,
        scan_completed_at=_NOW,
        scorecards=(success, failure),
    )
    assert report.total_agents_evaluated == 2
    assert report.successful_runs == 1


def test_meta_harness_report_carries_ab_comparison_when_present() -> None:
    ab = ABComparison(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        variant_a_path="A",
        variant_b_path="B",
        variant_a_pass_rate=0.9,
        variant_b_pass_rate=0.85,
        byte_equal=False,
        evaluated_at=_NOW,
    )
    report = MetaHarnessReport(
        customer_id="acme",
        run_id="r1",
        scan_started_at=_NOW,
        scan_completed_at=_NOW,
        ab_comparison=ab,
    )
    assert report.ab_comparison is ab
