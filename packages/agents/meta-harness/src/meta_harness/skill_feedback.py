"""G1 operator feedback parser — Task 7 (feedback-axis computation).

Reads operator ratings from the audit chain (canonical source per
G1-Q8) with a sidecar JSONL projection for cross-run persistence.
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

from charter.audit import AuditEntry, AuditLog
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
    """Canonical path for the per-skill operator-ratings JSONL projection.

    This file is a cache/projection of audit-chain
    ``agent.skill.operator_rated`` events — it enables cross-run
    persistence since the audit chain is per-run.  The audit chain
    is always the canonical source; the JSONL file is secondary.
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
    """Emit ``meta_harness.skill.effectiveness_error`` to the audit chain.

    Per CF #2: error paths route to the audit chain, never a bare
    ``_LOG.warning``.
    """
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
# Audit-chain reader (primary source per G1-Q8)
# ---------------------------------------------------------------------------


def _read_audit_chain_ratings(
    audit_log: AuditLog,
    *,
    skill_id: str,
    agent_id: str,
    tenant_id: str,
) -> Iterator[dict[str, object]]:
    """Yield operator-rating payloads from the audit chain.

    Reads the current run's ``audit.jsonl`` and yields payloads from
    every ``agent.skill.operator_rated`` entry matching the requested
    triple.
    """
    if not audit_log.path.is_file():
        return
    with open(audit_log.path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            entry = AuditEntry.from_json(stripped)
            if entry.action != "agent.skill.operator_rated":
                continue
            payload = entry.payload
            if payload.get("skill_id") != skill_id:
                continue
            if payload.get("agent_id") != agent_id:
                continue
            payload_tenant = payload.get("tenant_id", "default")
            if payload_tenant != tenant_id:
                continue
            yield payload


# ---------------------------------------------------------------------------
# Sidecar projection reader (secondary — cross-run persistence)
# ---------------------------------------------------------------------------


def _read_sidecar_projection_ratings(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    *,
    tenant_id: str,
) -> Iterator[dict[str, object]]:
    """Yield operator-rating records from the sidecar JSONL projection.

    This is a cache of ratings from prior runs.  Records already seen
    in the audit chain are deduplicated by the caller.
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
# Operator rating reader (audit-chain primary + sidecar projection)
# ---------------------------------------------------------------------------


def read_operator_ratings(
    agent_id: str,
    skill_id: str,
    *,
    audit_log: AuditLog,
    workspace_root: Path,
    tenant_id: str = "default",
) -> Iterator[dict[str, object]]:
    """Yield operator rating records for a given (agent, skill, tenant).

    Reads from the audit chain first (canonical source per G1-Q8), then
    from the sidecar JSONL projection for ratings from prior runs.
    Records already seen in the audit chain are not yielded again
    (deduplicated by ``(rated_by, rated_at)`` key).

    The audit chain is the source of truth for the current run; the
    sidecar ``operator-ratings.jsonl`` is a projection/cache maintained
    by Task 11's CLI rate-skill command.
    """
    seen: set[tuple[str, str]] = set()

    # Primary: audit chain (current run's canonical events).
    for payload in _read_audit_chain_ratings(
        audit_log,
        skill_id=skill_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
    ):
        rated_by = str(payload.get("rated_by", ""))
        rated_at = str(payload.get("rated_at", ""))
        seen.add((rated_by, rated_at))
        yield payload

    # Secondary: sidecar JSONL projection (prior-run cache).
    for record in _read_sidecar_projection_ratings(
        workspace_root,
        agent_id,
        skill_id,
        tenant_id=tenant_id,
    ):
        rated_by = str(record.get("rated_by", ""))
        rated_at = str(record.get("rated_at", ""))
        if (rated_by, rated_at) in seen:
            continue
        seen.add((rated_by, rated_at))
        yield record


# ---------------------------------------------------------------------------
# Feedback axis computation
# ---------------------------------------------------------------------------


def compute_feedback_axis(
    skill_id: str,
    agent_id: str,
    *,
    audit_log: AuditLog,
    workspace_root: Path,
    tenant_id: str = "default",
) -> FeedbackAxis:
    """Compute feedback-axis metrics from operator ratings.

    Reads operator-rating records for the given (agent, skill, tenant)
    triple from the audit chain (primary) and sidecar JSONL projection
    (secondary), computes the weighted feedback score, and returns a
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

    Per CF #2: read errors are emitted as
    ``meta_harness.skill.effectiveness_error`` rather than silently
    swallowed.
    """
    useful_count = 0
    neutral_count = 0
    harmful_count = 0

    try:
        for record in read_operator_ratings(
            agent_id=agent_id,
            skill_id=skill_id,
            audit_log=audit_log,
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
    except Exception as exc:
        _emit_effectiveness_error(
            audit_log,
            error_type="feedback_axis_read_failure",
            skill_id=skill_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
            exception_message=str(exc),
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
