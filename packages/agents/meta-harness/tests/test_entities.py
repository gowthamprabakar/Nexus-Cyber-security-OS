"""Tests — `meta_harness.entities` (Task 8 half).

6 tests covering both entity models:

1. ``AgentScorecard`` minimal valid construction + properties().
2. ``AgentScorecard`` XOR pass_rate / error.
3. ``AgentScorecard`` external_id format.
4. ``ABComparisonResult`` minimal valid construction + properties().
5. ``ABComparisonResult`` rejects identical variants.
6. ``ABComparisonResult`` external_id format.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from meta_harness.entities import ABComparisonResult, AgentScorecard
from pydantic import ValidationError

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# AgentScorecard
# ---------------------------------------------------------------------------


def test_agent_scorecard_success_valid() -> None:
    sc = AgentScorecard(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        total_cases=10,
        passed=9,
        failed=1,
        pass_rate=0.9,
        evaluated_at=_NOW,
    )
    props = sc.properties()
    assert props["agent_id"] == "cloud_posture"
    assert props["pass_rate"] == 0.9
    assert props["error"] is None
    assert props["evaluated_at"].startswith("2026-05-21")


def test_agent_scorecard_xor_rejects_neither() -> None:
    with pytest.raises(ValidationError, match=r"pass_rate.*or error"):
        AgentScorecard(
            customer_id="acme",
            run_id="r1",
            agent_id="cloud_posture",
            total_cases=0,
            passed=0,
            failed=0,
            evaluated_at=_NOW,
        )


def test_agent_scorecard_external_id_format() -> None:
    sc = AgentScorecard(
        customer_id="contoso",
        run_id="r99",
        agent_id="data_security",
        total_cases=0,
        passed=0,
        failed=0,
        error="boom",
        evaluated_at=_NOW,
    )
    assert sc.external_id == "contoso:r99:data_security"


# ---------------------------------------------------------------------------
# ABComparisonResult
# ---------------------------------------------------------------------------


def test_ab_comparison_result_valid() -> None:
    ab = ABComparisonResult(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        variant_a_path="/nlah/a",
        variant_b_path="/nlah/b",
        variant_a_pass_rate=0.9,
        variant_b_pass_rate=0.85,
        byte_equal=False,
        evaluated_at=_NOW,
    )
    props = ab.properties()
    assert props["byte_equal"] is False
    assert props["variant_a_pass_rate"] == 0.9


def test_ab_comparison_result_rejects_identical_variants() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        ABComparisonResult(
            customer_id="acme",
            run_id="r1",
            agent_id="cloud_posture",
            variant_a_path="/same",
            variant_b_path="/same",
            variant_a_pass_rate=0.5,
            variant_b_pass_rate=0.5,
            byte_equal=True,
            evaluated_at=_NOW,
        )


def test_ab_comparison_result_external_id_encodes_variants() -> None:
    ab = ABComparisonResult(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        variant_a_path="/nlah/a",
        variant_b_path="/nlah/b",
        variant_a_pass_rate=0.9,
        variant_b_pass_rate=0.85,
        byte_equal=False,
        evaluated_at=_NOW,
    )
    assert ab.external_id == "acme:r1:cloud_posture:/nlah/a:/nlah/b"
