"""G1 composite effectiveness scorer — Task 8.

Combines adoption, outcome, and feedback axes into a single
confidence-weighted composite score per G1-Q3 + Q9.

**Leaf-module discipline (per G1-Q6):** imports ONLY from
``meta_harness.schemas``, ``meta_harness.skill_adoption``,
``meta_harness.skill_outcome``, ``meta_harness.skill_feedback``,
stdlib, pydantic, ``charter.audit``, and ``shared.skill_telemetry``.
Does NOT import from ``skill_lifecycle``, ``skill_writer``,
``skill_eval_gate``, ``skill_approval``, or any storage/CLI modules.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from charter.audit import AuditLog
from shared.skill_telemetry import ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR

from meta_harness.schemas import (
    AxisBreakdown,
    EffectivenessAxes,
    EffectivenessReason,
    EffectivenessScore,
)
from meta_harness.skill_adoption import compute_adoption_metrics
from meta_harness.skill_feedback import compute_feedback_axis
from meta_harness.skill_outcome import compute_outcome_correlation

_logger = logging.getLogger(__name__)

# Q9 axis weights for the confidence-weighted composite.
_W_ADOPTION = 0.25
_W_OUTCOME = 0.35
_W_FEEDBACK = 0.40


# ---------------------------------------------------------------------------
# CF #2 effectiveness-error emission
# ---------------------------------------------------------------------------


def _emit_effectiveness_error(
    audit_log: AuditLog,
    *,
    error_type: str,
    skill_id: str,
    agent_id: str,
    tenant_id: str = "default",
    exception_message: str | None = None,
) -> None:
    """Emit ``meta_harness.skill.effectiveness_error`` to the audit chain."""
    import traceback

    payload: dict[str, object] = {
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "error_type": error_type,
        "stack_trace": traceback.format_exc(),
    }
    if exception_message is not None:
        payload["exception_message"] = exception_message
    audit_log.append(ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR, payload)


# ---------------------------------------------------------------------------
# Adoption score derivation
# ---------------------------------------------------------------------------


def _adoption_score(load_count: int) -> float | None:
    """Derive adoption-axis score from load count.

    Adoption is a binary signal: 1.0 if the skill has ever been loaded,
    None if no load events exist (zero confidence, drops out of composite).
    """
    return 1.0 if load_count > 0 else None


# ---------------------------------------------------------------------------
# Composite computation
# ---------------------------------------------------------------------------


def compute_effectiveness_score(
    skill_id: str,
    agent_id: str,
    *,
    audit_log: AuditLog,
    workspace_root: Path,
    tenant_id: str = "default",
) -> EffectivenessScore:
    """Compute the confidence-weighted composite effectiveness score.

    Calls all three axis compute functions — adoption (Task 5), outcome
    (Task 6), and feedback (Task 7) — and combines them with Q9 weights
    (0.25 / 0.35 / 0.40).

    Returns an ``EffectivenessScore`` with ``global_score=None``,
    ``confidence=0.0``, and ``reason="insufficient_data"`` when all three
    axes have zero confidence (no data for any axis).

    Per CF #2: axis computation failures are emitted as
    ``meta_harness.skill.effectiveness_error`` and re-raised.
    """
    now = datetime.now(UTC)
    reason: EffectivenessReason | None = None

    # Compute all three axes.
    try:
        adoption = compute_adoption_metrics(
            skill_id=skill_id,
            agent_id=agent_id,
            audit_log=audit_log,
            workspace_root=workspace_root,
            tenant_id=tenant_id,
        )
        outcome = compute_outcome_correlation(
            skill_id=skill_id,
            agent_id=agent_id,
            audit_log=audit_log,
            workspace_root=workspace_root,
            tenant_id=tenant_id,
        )
        feedback = compute_feedback_axis(
            skill_id=skill_id,
            agent_id=agent_id,
            audit_log=audit_log,
            workspace_root=workspace_root,
            tenant_id=tenant_id,
        )
    except Exception as exc:
        _emit_effectiveness_error(
            audit_log,
            error_type="effectiveness_error_during_aggregation",
            skill_id=skill_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
            exception_message=str(exc),
        )
        raise

    # Derive axis scores for the breakdown.
    a_score = _adoption_score(adoption.load_count)
    a_conf = adoption.confidence
    o_score = outcome.correlation_score
    o_conf = outcome.confidence
    f_score = feedback.feedback_score
    f_conf = feedback.confidence

    # Confidence-weighted composite per Q9.
    numerator = (
        _W_ADOPTION * (a_score or 0.0) * a_conf
        + _W_OUTCOME * (o_score or 0.0) * o_conf
        + _W_FEEDBACK * (f_score or 0.0) * f_conf
    )
    denominator = _W_ADOPTION * a_conf + _W_OUTCOME * o_conf + _W_FEEDBACK * f_conf

    if denominator > 0.0:
        composite_score: float | None = numerator / denominator
        composite_confidence = denominator
        axes_breakdown: EffectivenessAxes | None = EffectivenessAxes(
            adoption=AxisBreakdown(score=a_score or 0.0, confidence=a_conf),
            outcome=AxisBreakdown(score=o_score or 0.0, confidence=o_conf),
            feedback=AxisBreakdown(score=f_score or 0.0, confidence=f_conf),
        )
    else:
        composite_score = None
        composite_confidence = 0.0
        axes_breakdown = None
        reason = EffectivenessReason.INSUFFICIENT_DATA

    return EffectivenessScore(
        skill_id=skill_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        global_score=composite_score,
        confidence=composite_confidence,
        axes_breakdown=axes_breakdown,
        reason=reason,
        computed_at=now,
    )


__all__ = [
    "compute_effectiveness_score",
]
