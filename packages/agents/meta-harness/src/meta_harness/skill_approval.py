"""Skill approval workflow — Task 10 of A.4 v0.2.

File-based approval per Q5. No UI in v0.2 — S.1 Console is explicitly
deferred. CLI subcommands are wired by Task 15:

* ``meta-harness approve-skill <skill_id>``
* ``meta-harness reject-skill <skill_id> --reason <text>``

Three workflow paths once the eval-gate has run (Task 8):

1. **Eval-gate FAIL** — caller invokes ``reject_candidate`` directly;
   the shadow SKILL.md is removed and a ``DeploymentDecision(deployed=False)``
   is emitted.
2. **Eval-gate PASS + class already registered** — caller invokes
   ``auto_deploy_candidate``; the candidate is promoted from the shadow
   path to the canonical bundled NLAH path, and the registry's
   ``deployed_skill_ids`` / ``deployed_tool_sequence_hashes`` are
   updated. ``DeploymentDecision(approval_mode=AUTO_APPROVED)``.
3. **Eval-gate PASS + class NEW** — caller invokes
   ``write_candidate_notification`` to drop a markdown file the
   operator can read; the operator then runs ``approve-skill`` (calls
   ``approve_candidate``) or ``reject-skill``. On approve, the class is
   registered AND the candidate is promoted.
   ``DeploymentDecision(approval_mode=OPERATOR_APPROVED)``.

Promotion shape (shadow → canonical):

* **Shadow** ``<workspace>/.nexus/candidate-skills/<agent>/<skill_id>/SKILL.md``
  (written by Task 7).
* **Canonical** ``<workspace>/packages/agents/<dirname>/src/<agent>/nlah/skills/<skill_id>/SKILL.md``.

On promotion ``deployment_status`` flips ``CANDIDATE → DEPLOYED`` and
the shadow file is removed so it cannot be re-promoted by accident.

The registry returned by ``approve_candidate`` / ``auto_deploy_candidate``
is the **new** registry; callers are responsible for calling
``skill_registry.save_skill_class_registry`` to persist it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from meta_harness.schemas import (
    DeploymentDecision,
    EvalGateResult,
    SkillApprovalMode,
    SkillCandidate,
    SkillDeploymentStatus,
)
from meta_harness.skill_format import write_skill_md
from meta_harness.skill_registry import (
    SkillClassRegistry,
    record_deployment,
    register_class,
)


class SkillApprovalError(RuntimeError):
    """Raised when the approval workflow is invoked with inconsistent
    state — e.g. ``decide_auto_deployable`` called with a failed
    eval-gate, or ``auto_deploy_candidate`` called on an unregistered
    class. The caller routed wrong; this is a bug, not a soft state."""


def compute_canonical_skill_path(
    *,
    workspace_root: Path | str,
    agent_id: str,
    skill_id: str,
) -> Path:
    """Canonical bundled-NLAH path for a deployed skill.

    Mirrors ``meta_harness.skill_discovery.default_bundled_nlah_dir`` —
    ``<workspace>/packages/agents/<kebab>/src/<snake>/nlah/skills/<skill_id>/SKILL.md``.
    """
    dirname = agent_id.replace("_", "-")
    return (
        Path(workspace_root)
        / "packages"
        / "agents"
        / dirname
        / "src"
        / agent_id
        / "nlah"
        / "skills"
        / skill_id
        / "SKILL.md"
    )


def compute_notification_path(workspace_root: Path | str, skill_id: str) -> Path:
    """Operator-readable notification path for a pending candidate.

    Lives directly in ``<workspace>/`` so the operator sees it on
    ``ls`` of the workspace. ``skill_id`` contains a forward slash
    (``<category>/<skill-name>``); flatten it to ``__`` so the
    filename stays POSIX-safe.
    """
    safe = skill_id.replace("/", "__")
    return Path(workspace_root) / f"skill_candidate_{safe}.md"


def write_candidate_notification(
    *,
    candidate: SkillCandidate,
    eval_gate: EvalGateResult,
    workspace_root: Path | str,
) -> Path:
    """Write the operator-approval-pending markdown notification.

    Caller invokes this only when ``decide_auto_deployable`` returned
    ``None`` (eval-gate passed + class NEW). The markdown carries the
    candidate's identifying metadata, the eval-gate verdict, and the
    CLI commands the operator runs to approve or reject.
    """
    path = compute_notification_path(workspace_root, candidate.skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    skill = candidate.skill
    body = f"""# Candidate skill awaiting operator approval

- **skill_id**: `{candidate.skill_id}`
- **target_agent**: `{skill.target_agent}`
- **category**: `{skill.category}` (first skill in this class)
- **shadow_path**: `{candidate.shadow_path}`
- **emitted_at**: `{candidate.emitted_at.isoformat()}`

## Eval-gate verdict

- **passed**: {eval_gate.passed}
- **baseline_pass_rate**: {eval_gate.baseline_pass_rate}
- **candidate_pass_rate**: {eval_gate.candidate_pass_rate}
- **per_case_regressions**: {len(eval_gate.per_case_regressions)} case(s)
- **evaluated_at**: `{eval_gate.evaluated_at.isoformat()}`

## Approve

```
meta-harness approve-skill {candidate.skill_id}
```

## Reject

```
meta-harness reject-skill {candidate.skill_id} --reason "<text>"
```
"""
    path.write_text(body, encoding="utf-8")
    return path


def decide_auto_deployable(
    *,
    candidate: SkillCandidate,
    registry: SkillClassRegistry,
    eval_gate: EvalGateResult,
) -> SkillApprovalMode | None:
    """Determine the deployment path for an eval-gate-passing candidate.

    Returns:
        ``SkillApprovalMode.AUTO_APPROVED`` — class already registered;
        caller should invoke ``auto_deploy_candidate``.

        ``None`` — class is new; caller should call
        ``write_candidate_notification`` and wait for the operator's
        CLI decision (``approve_candidate`` or ``reject_candidate``).

    Raises:
        SkillApprovalError: eval-gate did not pass. Callers must route
        directly to ``reject_candidate``; consulting this function for
        a failed gate is a routing bug.
    """
    if not eval_gate.passed:
        raise SkillApprovalError(
            f"decide_auto_deployable called with failed eval-gate "
            f"for skill_id={candidate.skill_id!r}; callers must reject "
            "directly via reject_candidate"
        )
    if registry.is_class_registered(
        candidate.skill.target_agent,
        candidate.skill.category,
    ):
        return SkillApprovalMode.AUTO_APPROVED
    return None


def _promote_to_canonical(
    candidate: SkillCandidate,
    *,
    workspace_root: Path | str,
) -> Path:
    """Move SKILL.md from shadow to canonical; flip status to DEPLOYED.

    The shadow ``SKILL.md`` file is removed after the canonical copy is
    written so it cannot be re-promoted by accident.
    """
    deployed_skill = candidate.skill.model_copy(
        update={"deployment_status": SkillDeploymentStatus.DEPLOYED}
    )
    canonical_path = compute_canonical_skill_path(
        workspace_root=workspace_root,
        agent_id=candidate.skill.target_agent,
        skill_id=candidate.skill_id,
    )
    write_skill_md(deployed_skill, canonical_path)
    shadow_path = Path(candidate.shadow_path)
    if shadow_path.is_file():
        shadow_path.unlink()
    return canonical_path


def approve_candidate(
    candidate: SkillCandidate,
    *,
    registry: SkillClassRegistry,
    workspace_root: Path | str,
    decided_at: datetime | None = None,
) -> tuple[DeploymentDecision, SkillClassRegistry]:
    """Operator-approved deployment — first-of-class path.

    Promotes the candidate to its canonical path, registers the class
    in the registry (or records a refinement if the class was already
    registered — defensive idempotency for the case where the operator
    approves a refinement via the CLI instead of letting it
    auto-deploy), and returns the populated ``DeploymentDecision`` +
    the updated registry. Callers must persist the new registry via
    ``skill_registry.save_skill_class_registry``.
    """
    when = decided_at if decided_at is not None else datetime.now(UTC)
    canonical_path = _promote_to_canonical(candidate, workspace_root=workspace_root)
    new_registry = register_class(
        registry,
        agent_id=candidate.skill.target_agent,
        category=candidate.skill.category,
        skill_id=candidate.skill_id,
        tool_sequence_hash=candidate.tool_sequence_hash,
        approved_at=when,
    )
    if new_registry is registry or new_registry == registry:
        # register_class was a no-op — the class was already registered.
        # Operator approved a refinement explicitly; record it.
        new_registry = record_deployment(
            registry,
            agent_id=candidate.skill.target_agent,
            category=candidate.skill.category,
            skill_id=candidate.skill_id,
            tool_sequence_hash=candidate.tool_sequence_hash,
        )
    decision = DeploymentDecision(
        skill_id=candidate.skill_id,
        target_agent=candidate.skill.target_agent,
        category=candidate.skill.category,
        deployed=True,
        approval_mode=SkillApprovalMode.OPERATOR_APPROVED,
        deployed_path=str(canonical_path),
        decided_at=when,
    )
    return decision, new_registry


def auto_deploy_candidate(
    candidate: SkillCandidate,
    *,
    registry: SkillClassRegistry,
    workspace_root: Path | str,
    decided_at: datetime | None = None,
) -> tuple[DeploymentDecision, SkillClassRegistry]:
    """Auto-deployed refinement — class is already operator-approved.

    Raises ``SkillApprovalError`` if the class is not registered (the
    caller routed wrong — first-of-class requires
    ``approve_candidate`` via the operator-notification flow).
    """
    when = decided_at if decided_at is not None else datetime.now(UTC)
    if not registry.is_class_registered(
        candidate.skill.target_agent,
        candidate.skill.category,
    ):
        raise SkillApprovalError(
            f"auto_deploy_candidate called for unregistered class "
            f"({candidate.skill.target_agent!r}, {candidate.skill.category!r}); "
            "first-of-class requires approve_candidate"
        )
    canonical_path = _promote_to_canonical(candidate, workspace_root=workspace_root)
    new_registry = record_deployment(
        registry,
        agent_id=candidate.skill.target_agent,
        category=candidate.skill.category,
        skill_id=candidate.skill_id,
        tool_sequence_hash=candidate.tool_sequence_hash,
    )
    decision = DeploymentDecision(
        skill_id=candidate.skill_id,
        target_agent=candidate.skill.target_agent,
        category=candidate.skill.category,
        deployed=True,
        approval_mode=SkillApprovalMode.AUTO_APPROVED,
        deployed_path=str(canonical_path),
        decided_at=when,
    )
    return decision, new_registry


def reject_candidate(
    candidate: SkillCandidate,
    *,
    rejection_reason: str,
    decided_at: datetime | None = None,
) -> DeploymentDecision:
    """Reject and remove the shadow SKILL.md.

    Called for either an eval-gate failure (caller wires
    ``eval_gate.passed is False``) or an operator-driven rejection via
    the ``reject-skill`` CLI command.
    """
    when = decided_at if decided_at is not None else datetime.now(UTC)
    shadow_path = Path(candidate.shadow_path)
    if shadow_path.is_file():
        shadow_path.unlink()
    return DeploymentDecision(
        skill_id=candidate.skill_id,
        target_agent=candidate.skill.target_agent,
        category=candidate.skill.category,
        deployed=False,
        rejection_reason=rejection_reason,
        decided_at=when,
    )


__all__ = [
    "SkillApprovalError",
    "approve_candidate",
    "auto_deploy_candidate",
    "compute_canonical_skill_path",
    "compute_notification_path",
    "decide_auto_deployable",
    "reject_candidate",
    "write_candidate_notification",
]
