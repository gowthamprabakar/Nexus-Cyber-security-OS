"""G1 backwards-compat handler — Task 10.

Graceful degradation for agents not yet emitting skill-lifecycle events.
Per Q7 (Option A): non-emitting agents yield confidence=0.0 with an
explicit ``agent_not_emitting_events`` reason rather than the generic
``insufficient_data``.

**Leaf-module discipline (per G1-Q6):** imports ONLY from
``meta_harness.schemas``, ``meta_harness.effectiveness_store``,
``charter.audit``, stdlib, pydantic, and ``shared.skill_telemetry``.
Does NOT import from Tasks 5/6/7/8 computation modules or the
``skill_lifecycle`` family.
"""

from __future__ import annotations

import json
import logging
from enum import StrEnum
from pathlib import Path

from charter.audit import AuditEntry, AuditLog
from shared.skill_telemetry import ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR

from meta_harness.schemas import EffectivenessReason, EffectivenessScore

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Agent emission status
# ---------------------------------------------------------------------------


class AgentEmissionStatus(StrEnum):
    """Whether an agent has emitted skill-lifecycle events.

    ``emitting``: at least one ``agent.skill.loaded`` or
    ``agent.skill.contributed`` event found in the sidecar.

    ``silent``: no skill-lifecycle events found anywhere — the agent
    has never been instrumented for effectiveness scoring.

    ``unknown``: events exist in the audit chain but no sidecar
    projection is present — cannot confidently determine status.
    """

    EMITTING = "emitting"
    SILENT = "silent"
    UNKNOWN = "unknown"


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
# Sidecar scan helper
# ---------------------------------------------------------------------------

_SIDECAR_ACTIONS = frozenset({"agent.skill.loaded", "agent.skill.contributed"})


def _agent_has_sidecar_events(workspace_root: Path, agent_id: str) -> bool:
    """Check whether any skill under *agent_id* has emitted lifecycle events."""
    base = workspace_root / ".nexus" / "deployed-skills" / agent_id
    if not base.is_dir():
        return False
    for skill_dir in base.iterdir():
        if not skill_dir.is_dir():
            continue
        sidecar = skill_dir / "run-events.jsonl"
        if not sidecar.is_file():
            continue
        try:
            for line in sidecar.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                record = json.loads(stripped)
                if record.get("action") in _SIDECAR_ACTIONS:
                    return True
        except (json.JSONDecodeError, OSError):
            continue
    return False


# ---------------------------------------------------------------------------
# Audit-chain scan helper
# ---------------------------------------------------------------------------


def _audit_chain_has_agent_events(audit_log: AuditLog, agent_id: str) -> bool:
    """Check whether the current run's audit chain has events for *agent_id*."""
    if not audit_log.path.is_file():
        return False
    try:
        for line in audit_log.path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            entry = AuditEntry.from_json(stripped)
            if entry.action in _SIDECAR_ACTIONS:
                payload = entry.payload
                if payload.get("agent_id") == agent_id:
                    return True
    except (json.JSONDecodeError, OSError):
        return False
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_agent_emission_status(
    agent_id: str,
    *,
    audit_log: AuditLog,
    workspace_root: Path,
) -> AgentEmissionStatus:
    """Determine whether an agent has emitted skill-lifecycle events.

    Checks the sidecar ``run-events.jsonl`` files first (cross-run
    persistence), then falls back to the current run's audit chain.

    Returns:
    - ``emitting``: at least one lifecycle event found in the sidecar.
    - ``unknown``: no sidecar events but audit chain has entries for
      this agent (events exist but no persistent projection).
    - ``silent``: no lifecycle events found anywhere.
    """
    try:
        if _agent_has_sidecar_events(workspace_root, agent_id):
            return AgentEmissionStatus.EMITTING
        if _audit_chain_has_agent_events(audit_log, agent_id):
            return AgentEmissionStatus.UNKNOWN
        return AgentEmissionStatus.SILENT
    except Exception as exc:
        _emit_effectiveness_error(
            audit_log,
            error_type="emission_status_detection_failure",
            skill_id="",  # agent-level check, no specific skill
            agent_id=agent_id,
            exception_message=str(exc),
        )
        raise


def apply_backwards_compat_reason(
    score: EffectivenessScore,
    agent_id: str,
    *,
    audit_log: AuditLog,
    workspace_root: Path,
) -> EffectivenessScore:
    """Apply the backwards-compat reason to a zero-confidence score.

    When a skill has zero confidence because the agent has never emitted
    lifecycle events, the reason is upgraded from ``insufficient_data``
    to ``agent_not_emitting_events``.  This lets downstream consumers
    (GEPA v0.2.5, CLI) distinguish "no data yet" from "agent never
    instrumented."

    Scores with ``confidence > 0`` or reasons other than
    ``insufficient_data`` are returned unchanged.
    """
    if score.confidence > 0.0:
        return score
    if score.reason != EffectivenessReason.INSUFFICIENT_DATA:
        return score

    try:
        status = detect_agent_emission_status(
            agent_id=agent_id,
            audit_log=audit_log,
            workspace_root=workspace_root,
        )
    except Exception:
        _logger.warning(
            "Failed to detect emission status for agent %s; preserving original reason",
            agent_id,
            exc_info=True,
        )
        return score

    if status == AgentEmissionStatus.SILENT:
        return score.model_copy(update={"reason": EffectivenessReason.AGENT_NOT_EMITTING_EVENTS})
    return score


__all__ = [
    "AgentEmissionStatus",
    "apply_backwards_compat_reason",
    "detect_agent_emission_status",
]
