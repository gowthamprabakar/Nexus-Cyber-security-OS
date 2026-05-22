"""Stage 6 SKILL_TRIGGER + Stage 7 SKILL_CREATE wiring — Task 13.

End-to-end orchestrator that threads Tasks 6 / 7 / 8 / 9 / 10 / 12 into a
single per-run helper the driver invokes between Stage 5 REPORT and the
renamed Stage 8 HANDOFF.

Pipeline per evaluated agent:

1. Load the agent's audit-chain entries via ``audit_chain_loader``.
2. Apply ``detect_skill_trigger`` (Task 6) using the registry's
   deployed-hash set (Task 9) as the novelty input.
3. On trigger:
   a. ``write_skill_candidate`` (Task 7) — LLM composes SKILL.md.
   b. ``emit_skill_candidate_emitted`` (Task 12) — audit-chain entry.
   c. ``run_skill_eval_gate`` (Task 8) — Option-B two-run gate.
   d. ``emit_skill_eval_gate_completed`` (Task 12) — pass OR fail.
   e. ``cache_eval_gate_result`` (Task 8) — persist verdict next to shadow.
   f. Routing (Task 10):
      * eval-gate FAIL → ``reject_candidate`` + ``emit_skill_rejected``.
      * eval-gate PASS + class registered → ``auto_deploy_candidate``
        + ``emit_skill_deployed`` + registry saved.
      * eval-gate PASS + class NEW → ``write_candidate_notification``;
        record skill_id in ``pending_operator_review`` (CLI from Task 15
        promotes via ``approve_candidate``/``reject_candidate``).

The helper SKIPS the entire lifecycle when any of these inputs is
``None``:

* ``llm_provider`` — Task 7 needs an LLM.
* ``audit_chain_loader`` — no chain to scan.
* ``eval_runner_loader`` — Task 8 needs a target-agent runner.

Skipping returns an empty ``SkillLifecycleSummary`` — same shape the
v0.1 backwards-compat probe checks for.

Errors that interrupt one candidate (eval-gate empty cases, LLM
failure, etc.) are logged + that candidate is dropped from the
summary; the loop continues to the next candidate.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from charter.audit import AuditLog
from charter.llm import LLMProvider
from eval_framework.cases import load_cases
from eval_framework.runner import EvalRunner

from meta_harness.audit_emit import (
    emit_skill_candidate_emitted,
    emit_skill_deployed,
    emit_skill_eval_gate_completed,
    emit_skill_rejected,
)
from meta_harness.eval.batch import CasesRootResolver
from meta_harness.schemas import (
    DeploymentDecision,
    EvalGateResult,
    Scorecard,
    SkillApprovalMode,
    SkillLifecycleSummary,
)
from meta_harness.skill_approval import (
    SkillApprovalError,
    approve_candidate,
    auto_deploy_candidate,
    decide_auto_deployable,
    reject_candidate,
    write_candidate_notification,
)
from meta_harness.skill_eval_gate import (
    SkillEvalGateError,
    cache_eval_gate_result,
    run_skill_eval_gate,
)
from meta_harness.skill_registry import (
    load_skill_class_registry,
    save_skill_class_registry,
)
from meta_harness.skill_triggers import detect_skill_trigger
from meta_harness.skill_writer import write_skill_candidate

_LOG = logging.getLogger(__name__)

_LIFECYCLE_AUDIT_FILENAME = "meta-harness-skill-lifecycle.jsonl"

AuditChainLoader = Callable[[str], list[dict[str, Any]]]
"""Maps an ``agent_id`` to its audit-chain entries (Mapping[str, Any] each).

Caller (CLI / driver) decides how to resolve the chain — read a JSONL
file, query the F.6 audit agent, etc. The helper stays decoupled from
filesystem layout."""

EvalRunnerLoader = Callable[[str], EvalRunner]
"""Maps an ``agent_id`` to its ``EvalRunner`` (production: from the
``nexus_eval_runners`` entry-point group; tests: a ``FakeRunner``)."""


async def run_skill_lifecycle(
    *,
    scorecards: list[Scorecard],
    customer_id: str,
    run_id: str,
    workspace_root: Path,
    cases_resolver: CasesRootResolver,
    audit_chain_loader: AuditChainLoader | None = None,
    llm_provider: LLMProvider | None = None,
    eval_runner_loader: EvalRunnerLoader | None = None,
) -> SkillLifecycleSummary:
    """Stage 6 SKILL_TRIGGER + Stage 7 SKILL_CREATE.

    Returns an empty summary (v0.1-equivalent shape) when any of the
    three lifecycle inputs is None. With all three provided, walks each
    successful scorecard and runs the per-agent lifecycle.
    """
    del customer_id  # currently unused; reserved for per-tenant routing post-SET-LOCAL fix
    if audit_chain_loader is None or llm_provider is None or eval_runner_loader is None:
        return SkillLifecycleSummary()

    registry = load_skill_class_registry(workspace_root)
    audit_log = AuditLog(
        path=workspace_root / ".nexus" / _LIFECYCLE_AUDIT_FILENAME,
        agent="meta_harness",
        run_id=run_id,
    )

    triggers_detected = 0
    candidates_emitted = 0
    eval_gate_results: list[EvalGateResult] = []
    deployments: list[DeploymentDecision] = []
    pending: list[str] = []

    for scorecard in scorecards:
        # Only attempt skill creation on successful runs — error
        # scorecards lack the audit-chain shape we need.
        if scorecard.pass_rate is None:
            continue

        audit_entries = audit_chain_loader(scorecard.agent_id)
        deployed_hashes = registry.deployed_tool_sequence_hashes(scorecard.agent_id)
        trigger = detect_skill_trigger(
            agent_id=scorecard.agent_id,
            run_id=scorecard.run_id,
            audit_entries=audit_entries,
            deployed_tool_sequence_hashes=deployed_hashes,
        )
        if trigger is None:
            continue
        triggers_detected += 1

        candidate = await _write_candidate_safely(
            trigger=trigger,
            workspace_root=workspace_root,
            llm_provider=llm_provider,
        )
        if candidate is None:
            continue
        candidates_emitted += 1
        emit_skill_candidate_emitted(audit_log, candidate=candidate)

        eval_result = await _run_eval_gate_safely(
            candidate=candidate,
            scorecard=scorecard,
            workspace_root=workspace_root,
            cases_resolver=cases_resolver,
            eval_runner_loader=eval_runner_loader,
            llm_provider=llm_provider,
        )
        if eval_result is None:
            continue
        eval_gate_results.append(eval_result)
        emit_skill_eval_gate_completed(audit_log, result=eval_result)
        cache_eval_gate_result(
            eval_result,
            workspace_root=workspace_root,
            agent_id=scorecard.agent_id,
            skill_id=candidate.skill_id,
        )

        if not eval_result.passed:
            decision = reject_candidate(
                candidate,
                rejection_reason=_failure_reason(eval_result),
            )
            emit_skill_rejected(audit_log, decision=decision)
            deployments.append(decision)
            continue

        mode = decide_auto_deployable(candidate=candidate, registry=registry, eval_gate=eval_result)
        if mode is SkillApprovalMode.AUTO_APPROVED:
            try:
                decision, registry = auto_deploy_candidate(
                    candidate,
                    registry=registry,
                    workspace_root=workspace_root,
                )
            except SkillApprovalError as exc:
                _LOG.warning(
                    "SKILL_CREATE auto-deploy failed for skill_id=%s: %s",
                    candidate.skill_id,
                    exc,
                )
                continue
            emit_skill_deployed(audit_log, decision=decision)
            deployments.append(decision)
            save_skill_class_registry(registry, workspace_root=workspace_root)
        else:
            # New class — operator approval required. Write notification
            # markdown + record skill_id for the report's pending list.
            write_candidate_notification(
                candidate=candidate,
                eval_gate=eval_result,
                workspace_root=workspace_root,
            )
            pending.append(candidate.skill_id)

    return SkillLifecycleSummary(
        triggers_detected=triggers_detected,
        candidates_emitted=candidates_emitted,
        eval_gate_results=tuple(eval_gate_results),
        deployments=tuple(deployments),
        pending_operator_review=tuple(pending),
    )


async def apply_operator_approval(
    *,
    skill_id: str,
    workspace_root: Path,
    decided_at: datetime | None = None,
) -> DeploymentDecision:
    """CLI ``meta-harness approve-skill <skill_id>`` entry point (Task 15).

    Loads the cached candidate's metadata from the registry-shaped state
    on disk, runs ``approve_candidate``, persists the updated registry.
    """
    raise NotImplementedError(
        "apply_operator_approval is the Task 15 CLI seam; "
        "Task 13 wires only the auto-deploy / notification paths."
    )


def _failure_reason(eval_result: EvalGateResult) -> str:
    if eval_result.candidate_pass_rate < eval_result.baseline_pass_rate:
        return (
            f"eval-gate FAIL: candidate_pass_rate={eval_result.candidate_pass_rate:.3f} "
            f"< baseline_pass_rate={eval_result.baseline_pass_rate:.3f}"
        )
    if eval_result.per_case_regressions:
        worst = max(eval_result.per_case_regressions, key=lambda r: r[1])
        return f"eval-gate FAIL: per-case regression {worst[0]} dropped {worst[1]:.1f} pct"
    return "eval-gate FAIL: unspecified"


async def _write_candidate_safely(
    *,
    trigger: Any,
    workspace_root: Path,
    llm_provider: LLMProvider,
) -> Any:
    audit_log_path = str(workspace_root / ".nexus" / _LIFECYCLE_AUDIT_FILENAME)
    try:
        return await write_skill_candidate(
            trigger=trigger,
            audit_log_path=audit_log_path,
            workspace_root=workspace_root,
            llm_provider=llm_provider,
            emitted_at=datetime.now(UTC),
        )
    except Exception as exc:
        _LOG.warning(
            "SKILL_CREATE write_skill_candidate failed for trigger=%s: %s",
            trigger,
            exc,
        )
        return None


async def _run_eval_gate_safely(
    *,
    candidate: Any,
    scorecard: Scorecard,
    workspace_root: Path,
    cases_resolver: CasesRootResolver,
    eval_runner_loader: EvalRunnerLoader,
    llm_provider: LLMProvider,
) -> EvalGateResult | None:
    try:
        cases = load_cases(cases_resolver(scorecard.agent_id))
        runner = eval_runner_loader(scorecard.agent_id)
        return await run_skill_eval_gate(
            candidate=candidate,
            workspace_root=workspace_root,
            cases=cases,
            runner=runner,
            llm_provider=llm_provider,
        )
    except SkillEvalGateError as exc:
        _LOG.warning(
            "SKILL_CREATE eval-gate skipped for skill_id=%s: %s",
            candidate.skill_id,
            exc,
        )
        return None
    except Exception as exc:
        _LOG.warning(
            "SKILL_CREATE eval-gate errored for skill_id=%s: %s",
            candidate.skill_id,
            exc,
        )
        return None


# Re-export for callers / tests
__all__ = [
    "AuditChainLoader",
    "EvalRunnerLoader",
    "apply_operator_approval",
    "run_skill_lifecycle",
]


# Keep ``approve_candidate`` reachable through this module so Task 15's
# CLI path can import everything it needs from one place.
_ = approve_candidate
