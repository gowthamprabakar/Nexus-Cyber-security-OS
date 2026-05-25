"""G1 effectiveness action constants and agent-side telemetry helpers.

SAFETY-CRITICAL — substrate touch on ``packages/shared/`` per G1 plan doc
Tasks 3 + 13 (ADR-007 v1.5 amendment). This module defines the 6 new
audit-action strings for the G1 post-deployment telemetry vocabulary.

Per G1-Q8-C (raw telemetry in sidecar JSONL; state transitions in audit
chain — following A.4 v0.2 verification record CF #6):

- **Sidecar-only actions (2):** ``agent.skill.loaded``,
  ``agent.skill.contributed`` — agent-emitted raw telemetry written to
  ``<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/run-events.jsonl``.
  These do NOT enter the hash-chained audit log.
- **Audit-chain actions (4):** ``agent.skill.outcome_correlated``,
  ``agent.skill.operator_rated``, ``meta_harness.skill.effectiveness_updated``,
  ``meta_harness.skill.effectiveness_error`` — A.4-emitted state transitions
  written to the hash-chained audit log.

Agent-side opt-in (per G1-Q7): 2-line addition — call
``emit_agent_skill_loaded`` at run start and
``emit_agent_skill_contributed`` at run end.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# G1 effectiveness action constants
# ---------------------------------------------------------------------------

# Agent-emitted (sidecar JSONL only)
ACTION_AGENT_SKILL_LOADED = "agent.skill.loaded"
ACTION_AGENT_SKILL_CONTRIBUTED = "agent.skill.contributed"

# A.4-emitted (audit chain)
ACTION_AGENT_SKILL_OUTCOME_CORRELATED = "agent.skill.outcome_correlated"
ACTION_AGENT_SKILL_OPERATOR_RATED = "agent.skill.operator_rated"
ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED = "meta_harness.skill.effectiveness_updated"
ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR = "meta_harness.skill.effectiveness_error"

# ---------------------------------------------------------------------------
# Hash-chain routing configuration (per G1-Q8-C)
# ---------------------------------------------------------------------------

_SIDECAR_ONLY_ACTIONS: frozenset[str] = frozenset(
    {
        ACTION_AGENT_SKILL_LOADED,
        ACTION_AGENT_SKILL_CONTRIBUTED,
    }
)

_AUDIT_CHAIN_ACTIONS: frozenset[str] = frozenset(
    {
        ACTION_AGENT_SKILL_OUTCOME_CORRELATED,
        ACTION_AGENT_SKILL_OPERATOR_RATED,
        ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED,
        ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
    }
)

ALL_EFFECTIVENESS_ACTIONS: frozenset[str] = _SIDECAR_ONLY_ACTIONS | _AUDIT_CHAIN_ACTIONS


def is_audit_chain_action(action: str) -> bool:
    """True if ``action`` must be emitted to the hash-chained audit log."""
    return action in _AUDIT_CHAIN_ACTIONS


def is_sidecar_only_action(action: str) -> bool:
    """True if ``action`` is sidecar-only (raw telemetry, no hash-chain entry)."""
    return action in _SIDECAR_ONLY_ACTIONS


# ---------------------------------------------------------------------------
# Sidecar path convention
# ---------------------------------------------------------------------------

_SIDECAR_DIR_NAME = ".nexus"
_SKILLS_DIR_NAME = "deployed-skills"
_EVENTS_FILE_NAME = "run-events.jsonl"


def _sidecar_events_path(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
) -> Path:
    """Canonical sidecar path for a skill's run-events JSONL.

    Returns ``<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/run-events.jsonl``
    per the G1 plan doc storage convention (mirrors Task 15 candidate-sidecar pattern).
    """
    return (
        workspace_root
        / _SIDECAR_DIR_NAME
        / _SKILLS_DIR_NAME
        / agent_id
        / skill_id
        / _EVENTS_FILE_NAME
    )


# ---------------------------------------------------------------------------
# Agent-side telemetry helpers (the 2-line opt-in per G1-Q7)
# ---------------------------------------------------------------------------


def emit_agent_skill_loaded(
    workspace_root: Path,
    skill_id: str,
    agent_id: str,
    run_id: str,
    *,
    tenant_id: str = "default",
) -> Path:
    """Emit ``agent.skill.loaded`` to sidecar JSONL (call at agent run start).

    Appends one JSON line to the sidecar ``run-events.jsonl`` recording that
    the named skill was loaded for this run.  Returns the path written to so
    the caller can verify emission.

    Per G1-Q8-C: this is sidecar-only raw telemetry — it does NOT enter the
    hash-chained audit log.
    """
    now = datetime.now(UTC)
    record: dict[str, object] = {
        "action": ACTION_AGENT_SKILL_LOADED,
        "skill_id": skill_id,
        "agent_id": agent_id,
        "run_id": run_id,
        "tenant_id": tenant_id,
        "loaded_at": now.isoformat(),
        "contributed_at": None,
    }
    path = _sidecar_events_path(workspace_root, agent_id, skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    return path


def emit_agent_skill_contributed(
    workspace_root: Path,
    skill_id: str,
    agent_id: str,
    run_id: str,
    *,
    tenant_id: str = "default",
) -> Path:
    """Emit ``agent.skill.contributed`` to sidecar JSONL (call at agent run end).

    Appends one JSON line to the sidecar ``run-events.jsonl`` recording that
    the named skill contributed to this run's outcome.  Returns the path
    written to so the caller can verify emission.

    Per G1-Q8-C: this is sidecar-only raw telemetry — it does NOT enter the
    hash-chained audit log.
    """
    now = datetime.now(UTC)
    record: dict[str, object] = {
        "action": ACTION_AGENT_SKILL_CONTRIBUTED,
        "skill_id": skill_id,
        "agent_id": agent_id,
        "run_id": run_id,
        "tenant_id": tenant_id,
        "loaded_at": None,
        "contributed_at": now.isoformat(),
    }
    path = _sidecar_events_path(workspace_root, agent_id, skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    return path


__all__ = [
    "ACTION_AGENT_SKILL_CONTRIBUTED",
    "ACTION_AGENT_SKILL_LOADED",
    "ACTION_AGENT_SKILL_OPERATOR_RATED",
    "ACTION_AGENT_SKILL_OUTCOME_CORRELATED",
    "ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR",
    "ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED",
    "ALL_EFFECTIVENESS_ACTIONS",
    "emit_agent_skill_contributed",
    "emit_agent_skill_loaded",
    "is_audit_chain_action",
    "is_sidecar_only_action",
]
