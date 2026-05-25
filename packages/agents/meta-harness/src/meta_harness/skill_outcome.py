"""G1 run-outcome correlator — Task 6 (outcome-axis computation).

Read-only consumer of sidecar ``run-events.jsonl`` files.  Computes
per-skill outcome-correlation metrics from ``agent.skill.contributed``
events.

Per G1-Q3: outcome is the SECOND axis of the composite effectiveness
score (after adoption, before feedback).  Correlation formula::

    (success_count + 0.5 * partial_count) / total_contributions

**Leaf-module discipline (per G1-Q6):** imports ONLY from
``meta_harness.schemas``, ``meta_harness.skill_adoption``, stdlib,
pydantic, ``charter.audit``, and ``shared.skill_telemetry``.  Does NOT
import from ``skill_lifecycle``, ``skill_writer``, ``skill_eval_gate``,
``skill_approval``, or any future effectiveness-computation modules
beyond adoption.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from charter.audit import AuditLog
from pydantic import BaseModel, ConfigDict, Field
from shared.skill_telemetry import ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR

from meta_harness.schemas import (
    _MAX_AGENT_ID_LENGTH,
    _MAX_PASS_RATE,
    _MAX_SKILL_ID_LENGTH,
    _MAX_TENANT_ID_LENGTH,
    _MIN_PASS_RATE,
)
from meta_harness.skill_adoption import read_run_events

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Outcome correlation model
# ---------------------------------------------------------------------------


class OutcomeCorrelation(BaseModel):
    """Per-skill outcome-axis metrics computed from sidecar JSONL.

    ``correlation_score`` is the weighted success rate — successes count
    fully, partials count half, failures count zero.  ``None`` when
    there are no contributed events to correlate.

    Confidence grows toward 1.0 as contribution count increases:
    ``confidence = min(1.0, total_contributions / 10.0)``.
    """

    model_config = ConfigDict(frozen=True)

    skill_id: str = Field(min_length=1, max_length=_MAX_SKILL_ID_LENGTH)
    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    tenant_id: str = Field(default="default", min_length=1, max_length=_MAX_TENANT_ID_LENGTH)
    success_count: int = Field(default=0, ge=0)
    failure_count: int = Field(default=0, ge=0)
    partial_count: int = Field(default=0, ge=0)
    correlation_score: float | None = Field(default=None, ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Sidecar outcome-event reader
# ---------------------------------------------------------------------------


def read_outcome_events(
    agent_id: str,
    skill_id: str,
    *,
    workspace_root: Path,
    tenant_id: str = "default",
) -> Iterator[dict[str, object]]:
    """Yield sidecar events relevant to outcome correlation.

    Wraps ``read_run_events`` and filters to ``agent.skill.contributed``
    events — only runs where the skill finished and reported an outcome
    are meaningful for the outcome axis.
    """
    for record in read_run_events(
        agent_id=agent_id,
        skill_id=skill_id,
        workspace_root=workspace_root,
        tenant_id=tenant_id,
    ):
        if record.get("action") != "agent.skill.contributed":
            continue
        yield record


# ---------------------------------------------------------------------------
# Outcome correlation computation
# ---------------------------------------------------------------------------


def _emit_effectiveness_error(
    audit_log: AuditLog,
    *,
    skill_id: str,
    agent_id: str,
    error_type: str,
    error_detail: str,
    tenant_id: str = "default",
) -> None:
    """Emit ``meta_harness.skill.effectiveness_error`` to the audit chain.

    Per CF #2: error paths route to the audit chain, never a bare
    ``_LOG.warning``.
    """
    import traceback

    audit_log.append(
        ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
        {
            "skill_id": skill_id,
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "error_type": error_type,
            "error_detail": error_detail,
            "stack_trace": traceback.format_exc(),
        },
    )


def compute_outcome_correlation(
    skill_id: str,
    agent_id: str,
    *,
    workspace_root: Path,
    tenant_id: str = "default",
    audit_log: AuditLog | None = None,
) -> OutcomeCorrelation:
    """Compute outcome-axis metrics from sidecar contributed events.

    Reads all sidecar events for the given (agent, skill, tenant) triple,
    filters to ``agent.skill.contributed`` events, and computes aggregate
    outcome metrics: success / failure / partial counts, weighted
    correlation score, and confidence.

    Events whose ``outcome`` field doesn't match ``success``, ``failure``,
    or ``partial`` are silently skipped — the outcome axis only considers
    explicitly annotated contributions.

    Returns ``OutcomeCorrelation`` with all counts zero,
    ``correlation_score=None``, and ``confidence=0.0`` when the sidecar
    file is missing or contains no matching contributed events.

    Per CF #2: when ``audit_log`` is provided and a sidecar read error
    occurs, the error is emitted as
    ``meta_harness.skill.effectiveness_error`` rather than silently
    swallowed.
    """
    success_count = 0
    failure_count = 0
    partial_count = 0

    try:
        for record in read_outcome_events(
            agent_id=agent_id,
            skill_id=skill_id,
            workspace_root=workspace_root,
            tenant_id=tenant_id,
        ):
            outcome = record.get("outcome", "")
            if outcome == "success":
                success_count += 1
            elif outcome == "failure":
                failure_count += 1
            elif outcome == "partial":
                partial_count += 1
    except Exception:
        if audit_log is not None:
            _emit_effectiveness_error(
                audit_log,
                skill_id=skill_id,
                agent_id=agent_id,
                error_type="outcome_correlation_read_failure",
                error_detail="compute_outcome_correlation failed reading sidecar events",
                tenant_id=tenant_id,
            )
        raise

    total = success_count + failure_count + partial_count
    correlation_score = (success_count + 0.5 * partial_count) / total if total > 0 else None

    confidence = min(1.0, total / 10.0)

    return OutcomeCorrelation(
        skill_id=skill_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        success_count=success_count,
        failure_count=failure_count,
        partial_count=partial_count,
        correlation_score=correlation_score,
        confidence=confidence,
    )


__all__ = [
    "OutcomeCorrelation",
    "compute_outcome_correlation",
    "read_outcome_events",
]
