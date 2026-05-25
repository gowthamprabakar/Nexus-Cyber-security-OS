"""G1 operator feedback parser — Task 7 (feedback-axis computation).

Read-only consumer of per-skill ``operator-ratings.jsonl`` files.
Computes feedback-axis metrics from ``agent.skill.operator_rated`` events.

Per G1-Q3: feedback is the THIRD axis of the composite effectiveness
score (after adoption and outcome).  Formula::

    raw = (useful_count - harmful_count) / total_count   # range [-1, 1]
    feedback_score = (raw + 1) / 2                        # range [0, 1]

**Leaf-module discipline (per G1-Q6):** imports ONLY from
``meta_harness.schemas``, stdlib, pydantic, ``charter.audit``, and
``shared.skill_telemetry``.  Does NOT import from ``skill_lifecycle``,
``skill_writer``, ``skill_eval_gate``, ``skill_approval``, or any
effectiveness-computation modules.
"""

from __future__ import annotations

import json
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

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feedback axis model
# ---------------------------------------------------------------------------


class FeedbackAxis(BaseModel):
    """Per-skill feedback-axis metrics computed from operator ratings.

    ``feedback_score`` is the normalized weighted rating — useful counts
    as +1, harmful as -1, neutral as 0 — mapped from [-1, 1] to [0, 1].
    ``None`` when there are no operator ratings.

    Confidence ramps faster than adoption/outcome (5 ratings → full
    confidence) because operator feedback is higher-quality signal than
    automated telemetry.
    """

    model_config = ConfigDict(frozen=True)

    skill_id: str = Field(min_length=1, max_length=_MAX_SKILL_ID_LENGTH)
    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    tenant_id: str = Field(default="default", min_length=1, max_length=_MAX_TENANT_ID_LENGTH)
    useful_count: int = Field(default=0, ge=0)
    neutral_count: int = Field(default=0, ge=0)
    harmful_count: int = Field(default=0, ge=0)
    feedback_score: float | None = Field(default=None, ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Operator-ratings path resolution
# ---------------------------------------------------------------------------


def _operator_ratings_path(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
) -> Path:
    """Canonical path for per-skill operator ratings JSONL.

    Distinct from sidecar ``run-events.jsonl`` — operator ratings are
    decision-level audit-chain events per G1-Q8, not raw telemetry.
    """
    return (
        workspace_root
        / ".nexus"
        / "deployed-skills"
        / agent_id
        / skill_id
        / "operator-ratings.jsonl"
    )


# ---------------------------------------------------------------------------
# Operator rating reader
# ---------------------------------------------------------------------------


def read_operator_ratings(
    agent_id: str,
    skill_id: str,
    *,
    workspace_root: Path,
    tenant_id: str = "default",
) -> Iterator[dict[str, object]]:
    """Yield operator rating records for a given (agent, skill, tenant).

    Reads the per-skill ``operator-ratings.jsonl`` file line by line.
    Malformed JSON lines are logged at warning level and skipped.
    """
    path = _operator_ratings_path(workspace_root, agent_id, skill_id)
    if not path.is_file():
        return
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                _logger.warning("Skipping malformed JSONL line %d in %s", lineno, path)
                continue
            record_tenant = record.get("tenant_id", "default")
            if record_tenant != tenant_id:
                continue
            yield record


# ---------------------------------------------------------------------------
# Feedback axis computation
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


def compute_feedback_axis(
    skill_id: str,
    agent_id: str,
    *,
    workspace_root: Path,
    tenant_id: str = "default",
    audit_log: AuditLog | None = None,
) -> FeedbackAxis:
    """Compute feedback-axis metrics from operator ratings.

    Reads operator-rating records for the given (agent, skill, tenant)
    triple, computes the weighted feedback score, and returns a
    ``FeedbackAxis`` with counts, score, and confidence.

    Rating interpretation:
    - ``useful``: +1 weight
    - ``neutral``: 0 weight
    - ``harmful``: -1 weight

    Raw score = (useful - harmful) / total, normalized to [0, 1] via
    ``(raw + 1) / 2``.  Returns ``feedback_score=None`` and
    ``confidence=0.0`` when there are no ratings.

    Confidence = ``min(1.0, total / 5.0)`` — faster ramp than
    adoption/outcome because operator ratings are decision-level signal.

    Per CF #2: when ``audit_log`` is provided and a read error occurs,
    the error is emitted as ``meta_harness.skill.effectiveness_error``.
    """
    useful_count = 0
    neutral_count = 0
    harmful_count = 0

    try:
        for record in read_operator_ratings(
            agent_id=agent_id,
            skill_id=skill_id,
            workspace_root=workspace_root,
            tenant_id=tenant_id,
        ):
            rating = record.get("rating", "")
            if rating == "useful":
                useful_count += 1
            elif rating == "neutral":
                neutral_count += 1
            elif rating == "harmful":
                harmful_count += 1
    except Exception:
        if audit_log is not None:
            _emit_effectiveness_error(
                audit_log,
                skill_id=skill_id,
                agent_id=agent_id,
                error_type="feedback_axis_read_failure",
                error_detail="compute_feedback_axis failed reading operator ratings",
                tenant_id=tenant_id,
            )
        raise

    total = useful_count + neutral_count + harmful_count
    if total > 0:
        raw = (useful_count - harmful_count) / total
        feedback_score = (raw + 1.0) / 2.0
    else:
        feedback_score = None

    confidence = min(1.0, total / 5.0)

    return FeedbackAxis(
        skill_id=skill_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        useful_count=useful_count,
        neutral_count=neutral_count,
        harmful_count=harmful_count,
        feedback_score=feedback_score,
        confidence=confidence,
    )


__all__ = [
    "FeedbackAxis",
    "compute_feedback_axis",
    "read_operator_ratings",
]
