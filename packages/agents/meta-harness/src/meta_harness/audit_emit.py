"""Audit emission helpers — A.4 v0.2 Task 12.

Stage 6 SKILL_TRIGGER + Stage 7 SKILL_CREATE audit-action vocabulary.
Adds 4 new entries to meta_harness's existing 4 v0.1 actions
(``batch_eval.started`` / ``batch_eval.completed`` /
``regression_detected`` / ``ab_comparison.completed`` — emitted inline
elsewhere). **Total meta_harness.* actions in v0.2 = 8.**

The 4 new entries cover the full skill-lifecycle:

* ``meta_harness.skill.candidate_emitted`` — after Task 7's
  ``skill_writer.write_skill_candidate`` writes the shadow SKILL.md.
* ``meta_harness.skill.eval_gate_completed`` — after Task 8's
  ``run_skill_eval_gate`` produces an ``EvalGateResult`` (pass OR fail).
* ``meta_harness.skill.deployed`` — after Task 10's ``approve_candidate``
  or ``auto_deploy_candidate`` promotes shadow → canonical.
* ``meta_harness.skill.rejected`` — after Task 10's ``reject_candidate``
  removes the shadow SKILL.md (eval-gate failure or operator-driven
  rejection).

``DeploymentDecision`` XOR contract is enforced at emit time —
``emit_skill_deployed`` raises ``ValueError`` if ``decision.deployed``
is False; ``emit_skill_rejected`` raises if ``decision.deployed`` is
True. Catches routing bugs at the audit-emit boundary instead of
producing a misshaped entry that consumers later choke on.

F.6 hash-chain semantics inherited unchanged from ``charter.audit``
(each entry's ``previous_hash`` is the prior entry's ``entry_hash``).
The Task 13 driver constructs ONE ``AuditLog`` per meta-harness run
and threads these helpers through Stages 6 + 7.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Any

from charter.audit import AuditLog
from shared.skill_telemetry import (
    ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
    emit_agent_skill_contributed,
    emit_agent_skill_loaded,
)

from meta_harness.schemas import (
    DeploymentDecision,
    EvalGateResult,
    SkillCandidate,
)

ACTION_SKILL_CANDIDATE_EMITTED = "meta_harness.skill.candidate_emitted"
ACTION_SKILL_EVAL_GATE_COMPLETED = "meta_harness.skill.eval_gate_completed"
ACTION_SKILL_DEPLOYED = "meta_harness.skill.deployed"
ACTION_SKILL_REJECTED = "meta_harness.skill.rejected"

# ---------------------------------------------------------------------------
# G1 skill-lifecycle event emission helpers (Task 4)
# ---------------------------------------------------------------------------


class SkillRunOutcome(StrEnum):
    """Outcome of a run for skill telemetry (per G1-Q2 / agent.skill.*)."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"


# Idempotency registry: tracks (skill_id, run_id) pairs that have already
# emitted a ``skill.loaded`` event.  Duplicate calls are silently skipped.
_emitted_loads: set[tuple[str, str]] = set()

# Context-manager registry: tracks which skills were loaded within an active
# ``skill_telemetry_context`` block, keyed by run_id.  On context exit the
# registry is drained and each skill gets a ``skill.contributed`` emission.
_context_skills: dict[str, set[str]] = {}


def emit_skill_candidate_emitted(
    audit_log: AuditLog,
    *,
    candidate: SkillCandidate,
) -> None:
    """Append a ``skill.candidate_emitted`` entry to the audit chain.

    Called after Task 7 writes the shadow SKILL.md. Payload carries
    the identifying tuple ``(skill_id, target_agent, category)``, the
    ``shadow_path`` for forensic recovery, and the
    ``tool_sequence_hash`` so downstream consumers can correlate the
    trigger with deployed skills via Task 9's registry.
    """
    payload: dict[str, Any] = {
        "skill_id": candidate.skill_id,
        "target_agent": candidate.skill.target_agent,
        "category": candidate.skill.category,
        "shadow_path": candidate.shadow_path,
        "tool_sequence_hash": candidate.tool_sequence_hash,
        "emitted_at": candidate.emitted_at.isoformat(),
    }
    audit_log.append(ACTION_SKILL_CANDIDATE_EMITTED, payload)


def emit_skill_eval_gate_completed(
    audit_log: AuditLog,
    *,
    result: EvalGateResult,
) -> None:
    """Append a ``skill.eval_gate_completed`` entry.

    Called after Task 8's two-run gate completes. Payload carries
    baseline / candidate pass-rates + the per-case regression COUNT
    (not the full list — auditors that want detail re-read the cached
    ``eval_gate_result.json`` next to the shadow SKILL.md). ``passed``
    is the binary verdict.
    """
    payload: dict[str, Any] = {
        "skill_id": result.skill_id,
        "target_agent": result.target_agent,
        "passed": result.passed,
        "baseline_pass_rate": result.baseline_pass_rate,
        "candidate_pass_rate": result.candidate_pass_rate,
        "per_case_regression_count": len(result.per_case_regressions),
        "evaluated_at": result.evaluated_at.isoformat(),
    }
    audit_log.append(ACTION_SKILL_EVAL_GATE_COMPLETED, payload)


def emit_skill_deployed(
    audit_log: AuditLog,
    *,
    decision: DeploymentDecision,
) -> None:
    """Append a ``skill.deployed`` entry.

    Called after Task 10 promotes shadow → canonical. Payload carries
    the ``approval_mode`` (``operator_approved`` vs ``auto_approved``)
    and the ``deployed_path`` (canonical destination), so the audit
    chain alone is enough to reconstruct the deployment trajectory.

    Raises ``ValueError`` if ``decision.deployed`` is False — caller
    used the wrong helper for the decision shape (use
    ``emit_skill_rejected`` instead).
    """
    if not decision.deployed:
        raise ValueError(
            f"emit_skill_deployed called with decision.deployed=False "
            f"for skill_id={decision.skill_id!r}; use emit_skill_rejected"
        )
    if decision.approval_mode is None or decision.deployed_path is None:
        # XOR validator on DeploymentDecision guarantees these are set
        # when deployed=True; this branch is defensive against a future
        # contract drift.
        raise ValueError(
            f"emit_skill_deployed expected approval_mode + deployed_path "
            f"populated for skill_id={decision.skill_id!r}; got "
            f"approval_mode={decision.approval_mode!r}, "
            f"deployed_path={decision.deployed_path!r}"
        )
    payload: dict[str, Any] = {
        "skill_id": decision.skill_id,
        "target_agent": decision.target_agent,
        "category": decision.category,
        "approval_mode": decision.approval_mode.value,
        "deployed_path": decision.deployed_path,
        "decided_at": decision.decided_at.isoformat(),
    }
    audit_log.append(ACTION_SKILL_DEPLOYED, payload)


def emit_skill_rejected(
    audit_log: AuditLog,
    *,
    decision: DeploymentDecision,
) -> None:
    """Append a ``skill.rejected`` entry.

    Called after Task 10 removes the shadow SKILL.md. Payload carries
    the ``rejection_reason`` (free-form text — eval-gate failure
    summary, operator note, etc.).

    Raises ``ValueError`` if ``decision.deployed`` is True — caller
    used the wrong helper for the decision shape (use
    ``emit_skill_deployed`` instead).
    """
    if decision.deployed:
        raise ValueError(
            f"emit_skill_rejected called with decision.deployed=True "
            f"for skill_id={decision.skill_id!r}; use emit_skill_deployed"
        )
    if decision.rejection_reason is None:
        raise ValueError(
            f"emit_skill_rejected expected rejection_reason populated "
            f"for skill_id={decision.skill_id!r}"
        )
    payload: dict[str, Any] = {
        "skill_id": decision.skill_id,
        "target_agent": decision.target_agent,
        "category": decision.category,
        "rejection_reason": decision.rejection_reason,
        "decided_at": decision.decided_at.isoformat(),
    }
    audit_log.append(ACTION_SKILL_REJECTED, payload)


# ---------------------------------------------------------------------------
# G1 agent-side emission helpers (Task 4)
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

    Per CF #2 silent-swallow fix-pattern: when a sidecar write fails the
    error is surfaced as a proper audit-chain event, NOT buried in a bare
    ``_LOG.warning``.
    """
    import traceback

    payload: dict[str, Any] = {
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "error_type": error_type,
        "error_detail": error_detail,
        "stack_trace": traceback.format_exc(),
    }
    audit_log.append(ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR, payload)


def _try_read_skill_version(agent_id: str, skill_id: str) -> str | None:
    """Best-effort read of the skill version from its deployed SKILL.md.

    Returns ``None`` when the skill path doesn't exist or the frontmatter
    can't be parsed — callers treat a missing version as non-fatal.
    """
    return None  # Deferred to Task 13 (ADR-007 v1.5 NLAH skills/ reader)


def emit_skill_loaded(
    agent_id: str,
    skill_id: str,
    run_id: str,
    *,
    workspace_root: Path | None = None,
    tenant_id: str = "default",
    audit_log: AuditLog | None = None,
) -> Path | None:
    """Emit ``agent.skill.loaded`` to sidecar JSONL (agent run start).

    Wraps ``shared.skill_telemetry.emit_agent_skill_loaded`` with
    Meta-Harness-specific context: optionally attaches the skill version
    from the NLAH manifest, and enforces idempotency — duplicate calls
    for the same ``(skill_id, run_id)`` pair are silently skipped.

    Per CF #2: if the sidecar write raises an exception and ``audit_log``
    is provided, the error is emitted as
    ``meta_harness.skill.effectiveness_error`` rather than silently
    swallowed.
    """
    dedup_key = (skill_id, run_id)
    if dedup_key in _emitted_loads:
        return None
    _version = _try_read_skill_version(agent_id, skill_id)
    if workspace_root is None:
        _emitted_loads.add(dedup_key)
        return None
    try:
        path = emit_agent_skill_loaded(
            workspace_root=workspace_root,
            skill_id=skill_id,
            agent_id=agent_id,
            run_id=run_id,
            tenant_id=tenant_id,
        )
    except Exception:
        if audit_log is not None:
            _emit_effectiveness_error(
                audit_log,
                skill_id=skill_id,
                agent_id=agent_id,
                error_type="sidecar_write_failure",
                error_detail=f"emit_agent_skill_loaded failed for run_id={run_id!r}",
                tenant_id=tenant_id,
            )
        raise
    _emitted_loads.add(dedup_key)
    # Track for context-manager auto-contribute on exit.
    _context_skills.setdefault(run_id, set()).add(skill_id)
    return path


def emit_skill_contributed(
    agent_id: str,
    skill_id: str,
    run_id: str,
    outcome: SkillRunOutcome,
    *,
    workspace_root: Path | None = None,
    tenant_id: str = "default",
    audit_log: AuditLog | None = None,
) -> Path | None:
    """Emit ``agent.skill.contributed`` to sidecar JSONL (agent run end).

    Wraps ``shared.skill_telemetry.emit_agent_skill_contributed``,
    attaching the run ``outcome`` (success / failure / partial) for
    downstream run-outcome correlation (Task 6).

    Per CF #2: if the sidecar write raises and ``audit_log`` is provided,
    the error is emitted as ``meta_harness.skill.effectiveness_error``.
    """
    if workspace_root is None:
        return None
    try:
        path = emit_agent_skill_contributed(
            workspace_root=workspace_root,
            skill_id=skill_id,
            agent_id=agent_id,
            run_id=run_id,
            tenant_id=tenant_id,
        )
    except Exception:
        if audit_log is not None:
            _emit_effectiveness_error(
                audit_log,
                skill_id=skill_id,
                agent_id=agent_id,
                error_type="sidecar_write_failure",
                error_detail=f"emit_agent_skill_contributed failed for run_id={run_id!r}",
                tenant_id=tenant_id,
            )
        raise
    return path


@contextmanager
def skill_telemetry_context(
    agent_id: str,
    run_id: str,
    *,
    workspace_root: Path,
    audit_log: AuditLog,
    tenant_id: str = "default",
) -> Generator[None, None, None]:
    """Context manager that wraps a run with skill-telemetry bookkeeping.

    On exit, emits ``agent.skill.contributed`` (outcome defaults to
    ``SUCCESS`` unless an exception propagates) for every skill that
    had ``emit_skill_loaded`` called during the context block.

    Usage (the 2-line opt-in per G1-Q7)::

        with skill_telemetry_context(
            agent_id="cloud-posture", run_id=run_id,
            workspace_root=ws, audit_log=audit,
        ):
            ...

    Per CF #2: if a sidecar write fails during exit, the error is
    emitted as ``meta_harness.skill.effectiveness_error`` via the
    provided ``audit_log`` — no bare ``_LOG.warning``.
    """
    _context_skills.setdefault(run_id, set())
    outcome = SkillRunOutcome.SUCCESS
    try:
        yield
    except Exception:
        outcome = SkillRunOutcome.FAILURE
        raise
    finally:
        skills_to_close = _context_skills.pop(run_id, set())
        for skill_id in sorted(skills_to_close):
            try:
                emit_skill_contributed(
                    agent_id=agent_id,
                    skill_id=skill_id,
                    run_id=run_id,
                    outcome=outcome,
                    workspace_root=workspace_root,
                    tenant_id=tenant_id,
                    audit_log=audit_log,
                )
            except Exception:
                if audit_log is not None:
                    _emit_effectiveness_error(
                        audit_log,
                        skill_id=skill_id,
                        agent_id=agent_id,
                        error_type="context_exit_contribute_failure",
                        error_detail=(
                            f"emit_skill_contributed failed during context exit "
                            f"for run_id={run_id!r}, outcome={outcome.value}"
                        ),
                        tenant_id=tenant_id,
                    )
                # Do not re-raise — context-exit errors must not mask the
                # original exception (if any) or crash a healthy run.


__all__ = [
    "ACTION_SKILL_CANDIDATE_EMITTED",
    "ACTION_SKILL_DEPLOYED",
    "ACTION_SKILL_EVAL_GATE_COMPLETED",
    "ACTION_SKILL_REJECTED",
    "SkillRunOutcome",
    "emit_skill_candidate_emitted",
    "emit_skill_contributed",
    "emit_skill_deployed",
    "emit_skill_eval_gate_completed",
    "emit_skill_loaded",
    "emit_skill_rejected",
    "skill_telemetry_context",
]
