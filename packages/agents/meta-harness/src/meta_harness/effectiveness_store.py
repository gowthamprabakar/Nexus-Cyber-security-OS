"""G1 effectiveness store — Task 9 (persistent storage layer).

Read/write effectiveness scores to workspace-scoped sidecar JSON files.
Per Q1: ``<workspace>/.nexus/deployed-skills/<agent_id>/<skill_id>/effectiveness.json``.

**Leaf-module discipline (per G1-Q6):** imports ONLY from
``meta_harness.schemas``, ``charter.audit``, stdlib, pydantic, and
``shared.skill_telemetry``.  Does NOT import from Tasks 5/6/7/8
computation modules — this is the storage layer, not computation.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from charter.audit import AuditLog
from shared.skill_telemetry import (
    ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
    ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED,
)

from meta_harness.schemas import EffectivenessScore

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sidecar path resolution
# ---------------------------------------------------------------------------


def _effectiveness_path(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
) -> Path:
    """Canonical path for the per-skill effectiveness sidecar JSON."""
    return (
        workspace_root / ".nexus" / "deployed-skills" / agent_id / skill_id / "effectiveness.json"
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
# Read
# ---------------------------------------------------------------------------


def get_effectiveness_score(
    skill_id: str,
    agent_id: str,
    *,
    workspace_root: Path,
    tenant_id: str = "default",
) -> EffectivenessScore | None:
    """Read a cached effectiveness score from the sidecar file.

    Returns ``None`` when the sidecar file is absent, unparseable, or
    belongs to a different tenant.
    """
    path = _effectiveness_path(workspace_root, agent_id, skill_id)
    if not path.is_file():
        return None
    try:
        data = path.read_text(encoding="utf-8")
        score = EffectivenessScore.model_validate_json(data)
    except (json.JSONDecodeError, ValueError) as exc:
        _logger.warning("Cannot parse effectiveness sidecar %s: %s", path, exc)
        return None
    if score.tenant_id != tenant_id:
        return None
    return score


# ---------------------------------------------------------------------------
# Write (atomic, idempotent audit emission)
# ---------------------------------------------------------------------------


def write_effectiveness_score(
    score: EffectivenessScore,
    *,
    audit_log: AuditLog,
    workspace_root: Path,
) -> None:
    """Atomically write an effectiveness score to the sidecar file.

    Uses a temp-file + rename pattern (POSIX atomic on the same
    filesystem).  Emits ``meta_harness.skill.effectiveness_updated`` to
    the audit chain when the score changes from its previous value.

    Idempotency: writing the same ``global_score`` and ``confidence``
    a second time does NOT emit a second audit event.

    Per CF #2: write failures are emitted as
    ``meta_harness.skill.effectiveness_error`` and re-raised.
    """
    path = _effectiveness_path(workspace_root, score.agent_id, score.skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Determine whether this is a change from the previous score.
    existing = get_effectiveness_score(
        skill_id=score.skill_id,
        agent_id=score.agent_id,
        workspace_root=workspace_root,
        tenant_id=score.tenant_id,
    )
    is_change = (
        existing is None
        or existing.global_score != score.global_score
        or existing.confidence != score.confidence
    )

    # Atomic write via temp-file + rename.
    tmp_path = path.with_suffix(".tmp")
    try:
        tmp_path.write_text(score.model_dump_json(indent=2), encoding="utf-8")
        tmp_path.rename(path)
    except OSError as exc:
        _emit_effectiveness_error(
            audit_log,
            error_type="effectiveness_store_write_failure",
            skill_id=score.skill_id,
            agent_id=score.agent_id,
            tenant_id=score.tenant_id,
            exception_message=str(exc),
        )
        raise

    # Emit audit event only on change.
    if is_change:
        audit_log.append(
            ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED,
            {
                "skill_id": score.skill_id,
                "agent_id": score.agent_id,
                "tenant_id": score.tenant_id,
                "old_global_score": existing.global_score if existing else None,
                "new_global_score": score.global_score,
                "old_confidence": existing.confidence if existing else 0.0,
                "new_confidence": score.confidence,
                "computed_at": score.computed_at.isoformat(),
            },
        )


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def list_deployed_skills_with_scores(
    workspace_root: Path,
    tenant_id: str = "default",
) -> list[tuple[str, str, EffectivenessScore | None]]:
    """Enumerate all deployed-skill directories and their cached scores.

    Walks ``<workspace>/.nexus/deployed-skills/`` and returns a list of
    ``(agent_id, skill_id, score_or_none)`` tuples.  Skills without a
    cached ``effectiveness.json`` (or whose score belongs to a different
    tenant) appear with ``None``.
    """
    base = workspace_root / ".nexus" / "deployed-skills"
    if not base.is_dir():
        return []

    results: list[tuple[str, str, EffectivenessScore | None]] = []
    for agent_dir in sorted(base.iterdir()):
        if not agent_dir.is_dir():
            continue
        agent_id = agent_dir.name
        for skill_dir in sorted(agent_dir.iterdir()):
            if not skill_dir.is_dir():
                continue
            skill_id = skill_dir.name
            score = get_effectiveness_score(
                skill_id=skill_id,
                agent_id=agent_id,
                workspace_root=workspace_root,
                tenant_id=tenant_id,
            )
            results.append((agent_id, skill_id, score))
    return results


__all__ = [
    "get_effectiveness_score",
    "list_deployed_skills_with_scores",
    "write_effectiveness_score",
]
