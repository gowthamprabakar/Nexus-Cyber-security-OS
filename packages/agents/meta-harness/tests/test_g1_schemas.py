"""G1 schema validation tests — Task 2 (effectiveness types).

12 tests covering the 5 new G1 pydantic types added to ``schemas.py``:
EffectivenessScore, SkillTelemetry, OperatorRating, RunOutcomeCorrelation,
EffectivenessReason, OperatorRatingValue, AxisBreakdown, EffectivenessAxes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from meta_harness.schemas import (
    AxisBreakdown,
    EffectivenessAxes,
    EffectivenessReason,
    EffectivenessScore,
    OperatorRating,
    OperatorRatingValue,
    RunOutcomeCorrelation,
    SkillTelemetry,
)
from pydantic import ValidationError

_NOW = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# EffectivenessScore — happy paths
# ---------------------------------------------------------------------------


def test_g1_effectiveness_score_nonzero_confidence_valid() -> None:
    """EffectivenessScore with confidence > 0 must carry global_score and axes_breakdown."""
    axes = EffectivenessAxes(
        adoption=AxisBreakdown(score=0.7, confidence=0.6),
        outcome=AxisBreakdown(score=0.8, confidence=0.5),
        feedback=AxisBreakdown(score=0.9, confidence=0.4),
    )
    score = EffectivenessScore(
        skill_id="sk_test_001",
        agent_id="cloud-posture",
        global_score=0.82,
        confidence=0.5,
        by_agent={"cloud-posture": 0.82},
        by_tenant={"default": 0.80},
        axes_breakdown=axes,
        computed_at=_NOW,
    )
    assert score.global_score == 0.82
    assert score.confidence == 0.5
    assert score.skill_id == "sk_test_001"
    assert score.tenant_id == "default"


def test_g1_effectiveness_score_zero_confidence_valid() -> None:
    """EffectivenessScore with zero confidence must have reason set, global_score=None."""
    score = EffectivenessScore(
        skill_id="sk_test_002",
        agent_id="cloud-posture",
        confidence=0.0,
        reason=EffectivenessReason.INSUFFICIENT_DATA,
        computed_at=_NOW,
    )
    assert score.global_score is None
    assert score.confidence == 0.0
    assert score.reason == EffectivenessReason.INSUFFICIENT_DATA
    assert score.axes_breakdown is None
    assert score.by_agent == {}
    assert score.by_tenant == {}


# ---------------------------------------------------------------------------
# EffectivenessScore — validation edge cases
# ---------------------------------------------------------------------------


def test_g1_zero_confidence_without_reason_raises() -> None:
    """confidence=0.0 with no reason → ValidationError."""
    with pytest.raises(ValidationError, match=r"confidence=0\.0 requires a reason"):
        EffectivenessScore(
            skill_id="sk_err_001",
            agent_id="cloud-posture",
            confidence=0.0,
            computed_at=_NOW,
        )


def test_g1_zero_confidence_with_global_score_raises() -> None:
    """confidence=0.0 with global_score not None → ValidationError."""
    with pytest.raises(ValidationError, match="global_score must be None"):
        EffectivenessScore(
            skill_id="sk_err_002",
            agent_id="cloud-posture",
            global_score=0.5,
            confidence=0.0,
            reason=EffectivenessReason.INSUFFICIENT_DATA,
            computed_at=_NOW,
        )


def test_g1_zero_confidence_with_axes_breakdown_raises() -> None:
    """confidence=0.0 with axes_breakdown not None → ValidationError."""
    axes = EffectivenessAxes(
        adoption=AxisBreakdown(score=0.5, confidence=0.1),
        outcome=AxisBreakdown(score=0.5, confidence=0.1),
        feedback=AxisBreakdown(score=0.5, confidence=0.1),
    )
    with pytest.raises(ValidationError, match="axes_breakdown must be None"):
        EffectivenessScore(
            skill_id="sk_err_003",
            agent_id="cloud-posture",
            confidence=0.0,
            reason=EffectivenessReason.AGENT_NOT_EMITTING_EVENTS,
            axes_breakdown=axes,
            computed_at=_NOW,
        )


def test_g1_nonzero_confidence_without_global_score_raises() -> None:
    """confidence > 0 with no global_score → ValidationError."""
    axes = EffectivenessAxes(
        adoption=AxisBreakdown(score=0.5, confidence=0.3),
        outcome=AxisBreakdown(score=0.5, confidence=0.3),
        feedback=AxisBreakdown(score=0.5, confidence=0.3),
    )
    with pytest.raises(ValidationError, match="global_score must not be None"):
        EffectivenessScore(
            skill_id="sk_err_004",
            agent_id="cloud-posture",
            confidence=0.3,
            axes_breakdown=axes,
            computed_at=_NOW,
        )


def test_g1_nonzero_confidence_without_axes_breakdown_raises() -> None:
    """confidence > 0 with no axes_breakdown → ValidationError."""
    with pytest.raises(ValidationError, match="axes_breakdown must not be None"):
        EffectivenessScore(
            skill_id="sk_err_005",
            agent_id="cloud-posture",
            global_score=0.5,
            confidence=0.3,
            computed_at=_NOW,
        )


# ---------------------------------------------------------------------------
# EffectivenessScore — by_agent / by_tenant constraint validation
# ---------------------------------------------------------------------------


def test_g1_by_agent_score_out_of_range_raises() -> None:
    """by_agent values must be in [0, 1]."""
    axes = EffectivenessAxes(
        adoption=AxisBreakdown(score=0.5, confidence=0.3),
        outcome=AxisBreakdown(score=0.5, confidence=0.3),
        feedback=AxisBreakdown(score=0.5, confidence=0.3),
    )
    with pytest.raises(ValidationError, match="out of"):
        EffectivenessScore(
            skill_id="sk_err_006",
            agent_id="cloud-posture",
            global_score=0.5,
            confidence=0.3,
            by_agent={"cloud-posture": 1.5},
            axes_breakdown=axes,
            computed_at=_NOW,
        )


def test_g1_by_tenant_score_out_of_range_raises() -> None:
    """by_tenant values must be in [0, 1]."""
    axes = EffectivenessAxes(
        adoption=AxisBreakdown(score=0.5, confidence=0.3),
        outcome=AxisBreakdown(score=0.5, confidence=0.3),
        feedback=AxisBreakdown(score=0.5, confidence=0.3),
    )
    with pytest.raises(ValidationError, match="out of"):
        EffectivenessScore(
            skill_id="sk_err_007",
            agent_id="cloud-posture",
            global_score=0.5,
            confidence=0.3,
            by_tenant={"default": -0.1},
            axes_breakdown=axes,
            computed_at=_NOW,
        )


# ---------------------------------------------------------------------------
# SkillTelemetry
# ---------------------------------------------------------------------------


def test_g1_skill_telemetry_valid() -> None:
    """SkillTelemetry constructs with loaded_at; contributed_at optional."""
    telemetry = SkillTelemetry(
        skill_id="sk_test_001",
        agent_id="cloud-posture",
        run_id="run_abc_001",
        loaded_at=_NOW,
    )
    assert telemetry.skill_id == "sk_test_001"
    assert telemetry.contributed_at is None
    assert telemetry.tenant_id == "default"

    # With contributed_at.
    telemetry2 = SkillTelemetry(
        skill_id="sk_test_001",
        agent_id="cloud-posture",
        run_id="run_abc_001",
        loaded_at=_NOW,
        contributed_at=_NOW,
    )
    assert telemetry2.contributed_at == _NOW


# ---------------------------------------------------------------------------
# OperatorRating
# ---------------------------------------------------------------------------


def test_g1_operator_rating_valid() -> None:
    """OperatorRating constructs with valid rating enum and optional note."""
    rating = OperatorRating(
        skill_id="sk_test_001",
        agent_id="cloud-posture",
        rating=OperatorRatingValue.USEFUL,
        note="Improved multi-region scan latency",
        rated_at=_NOW,
        rated_by="operator-praba",
    )
    assert rating.rating == OperatorRatingValue.USEFUL
    assert rating.note == "Improved multi-region scan latency"
    assert rating.rated_by == "operator-praba"

    # Without note.
    rating2 = OperatorRating(
        skill_id="sk_test_002",
        agent_id="cloud-posture",
        rating=OperatorRatingValue.HARMFUL,
        rated_at=_NOW,
        rated_by="operator-praba",
    )
    assert rating2.note is None
    assert rating2.rating == OperatorRatingValue.HARMFUL


# ---------------------------------------------------------------------------
# RunOutcomeCorrelation
# ---------------------------------------------------------------------------


def test_g1_run_outcome_correlation_contributed_implies_loaded() -> None:
    """skill_contributed=True requires skill_loaded=True."""
    # Valid.
    corr = RunOutcomeCorrelation(
        run_id="run_abc_001",
        skill_id="sk_test_001",
        agent_id="cloud-posture",
        skill_loaded=True,
        skill_contributed=True,
        run_success=True,
        correlated_at=_NOW,
    )
    assert corr.run_success

    # Invalid: contributed without loaded.
    with pytest.raises(ValidationError, match="skill_contributed"):
        RunOutcomeCorrelation(
            run_id="run_abc_002",
            skill_id="sk_test_001",
            agent_id="cloud-posture",
            skill_loaded=False,
            skill_contributed=True,
            run_success=True,
            correlated_at=_NOW,
        )


# ---------------------------------------------------------------------------
# JSON round-trip serialisation
# ---------------------------------------------------------------------------


def test_g1_effectiveness_score_json_round_trip() -> None:
    """EffectivenessScore serialises to JSON and back (matters for sidecar storage)."""
    axes = EffectivenessAxes(
        adoption=AxisBreakdown(score=0.7, confidence=0.6),
        outcome=AxisBreakdown(score=0.8, confidence=0.5),
        feedback=AxisBreakdown(score=0.9, confidence=0.4),
    )
    original = EffectivenessScore(
        skill_id="sk_roundtrip",
        agent_id="cloud-posture",
        global_score=0.82,
        confidence=0.5,
        by_agent={"cloud-posture": 0.82},
        by_tenant={"default": 0.80},
        axes_breakdown=axes,
        computed_at=_NOW,
    )
    json_str = original.model_dump_json()
    data = json.loads(json_str)
    restored = EffectivenessScore.model_validate(data)
    assert restored.global_score == original.global_score
    assert restored.confidence == original.confidence
    assert restored.skill_id == original.skill_id
    assert restored.by_agent == original.by_agent
    assert restored.by_tenant == original.by_tenant
    assert restored.axes_breakdown is not None
    assert restored.axes_breakdown.adoption.score == 0.7


def test_g1_zero_confidence_score_json_round_trip() -> None:
    """Zero-confidence EffectivenessScore round-trips with reason and null fields."""
    original = EffectivenessScore(
        skill_id="sk_zero_conf",
        agent_id="cloud-posture",
        confidence=0.0,
        reason=EffectivenessReason.AGENT_NOT_EMITTING_EVENTS,
        computed_at=_NOW,
    )
    json_str = original.model_dump_json()
    data = json.loads(json_str)
    restored = EffectivenessScore.model_validate(data)
    assert restored.global_score is None
    assert restored.confidence == 0.0
    assert restored.reason == EffectivenessReason.AGENT_NOT_EMITTING_EVENTS
    assert restored.axes_breakdown is None


# ---------------------------------------------------------------------------
# EffectivenessReason enum values
# ---------------------------------------------------------------------------


def test_g1_effectiveness_reason_all_values_match_plan_doc() -> None:
    """All 4 zero-confidence reasons match the G1 plan doc §2.7."""
    reasons = set(EffectivenessReason)
    assert reasons == {
        EffectivenessReason.AGENT_NOT_EMITTING_EVENTS,
        EffectivenessReason.INSUFFICIENT_DATA,
        EffectivenessReason.OPERATOR_MARKED_ARCHIVED,
        EffectivenessReason.EFFECTIVENESS_ERROR_DURING_AGGREGATION,
    }
