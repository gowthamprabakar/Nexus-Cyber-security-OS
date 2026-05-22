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

from typing import Any

from charter.audit import AuditLog

from meta_harness.schemas import (
    DeploymentDecision,
    EvalGateResult,
    SkillCandidate,
)

ACTION_SKILL_CANDIDATE_EMITTED = "meta_harness.skill.candidate_emitted"
ACTION_SKILL_EVAL_GATE_COMPLETED = "meta_harness.skill.eval_gate_completed"
ACTION_SKILL_DEPLOYED = "meta_harness.skill.deployed"
ACTION_SKILL_REJECTED = "meta_harness.skill.rejected"


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


__all__ = [
    "ACTION_SKILL_CANDIDATE_EMITTED",
    "ACTION_SKILL_DEPLOYED",
    "ACTION_SKILL_EVAL_GATE_COMPLETED",
    "ACTION_SKILL_REJECTED",
    "emit_skill_candidate_emitted",
    "emit_skill_deployed",
    "emit_skill_eval_gate_completed",
    "emit_skill_rejected",
]
