"""F.6 hash-chained audit-log wiring for A.1's 7-stage pipeline.

This module is a thin shim over `charter.audit.AuditLog` that defines:

1. The **action-name vocabulary** A.1 emits (`remediation.*` and
   `promotion.*`).
2. A small helper, `PipelineAuditor`, that owns the per-run `AuditLog`
   instance and exposes one method per pipeline stage. The driver (Task 12)
   constructs one `PipelineAuditor` per run and calls the methods at each
   stage boundary.

**Why a vocabulary file** — the F.6 5-axis query API (Task 16's runbook
will reference it) filters by `action` strings. Centralising A.1's
strings here means downstream consumers (D.7 cross-incident correlation,
S.1 console replay) can reason about A.1's audit trail without
string-grep guessing.

A.1 v0.1's 11 `remediation.*` actions:

| Stage | Action                              | Emitted by                                      |
| ----- | ----------------------------------- | ----------------------------------------------- |
| —     | `remediation.run_started`           | driver, once per run                            |
| 1     | `remediation.findings_ingested`     | driver, after Stage 1                           |
| 2     | `remediation.action_refused`        | per refused finding (AUTHZ filter)              |
| 2     | `remediation.blast_radius_refused`  | once when the cap is exceeded                   |
| 3     | `remediation.artifact_generated`    | per artifact                                    |
| 4     | `remediation.dry_run_completed`     | per artifact (succeeded OR failed)              |
| 5     | `remediation.execute_completed`     | per artifact (succeeded; pre/post hashes)       |
| 5     | `remediation.execute_failed`        | per artifact (failed before validate)           |
| 6     | `remediation.validate_completed`    | per artifact (validated OR requires_rollback)   |
| 7     | `remediation.rollback_completed`    | per artifact (only when Stage 6 said roll back) |
| —     | `remediation.run_completed`         | driver, once per run                            |

A.1 v0.1.1 adds 9 `promotion.*` actions (see [earned-autonomy pipeline
plan](../../../../../../docs/superpowers/plans/2026-05-17-a-1-earned-autonomy-pipeline.md)):

| Phase           | Action                                  | Emitted by                                                   |
| --------------- | --------------------------------------- | ------------------------------------------------------------ |
| evidence        | `promotion.evidence.stage1`             | driver, per Stage-1 artifact emitted                         |
| evidence        | `promotion.evidence.stage2`             | driver, per successful dry-run                               |
| evidence        | `promotion.evidence.stage3`             | driver, per validated execute                                |
| evidence        | `promotion.evidence.unexpected_rollback`| driver, per rollback NOT attributable to webhook             |
| proposal        | `promotion.advance.proposed`            | reconciler, when criteria are met                            |
| transition      | `promotion.advance.applied`             | CLI `remediation promotion advance`                          |
| transition      | `promotion.demote.applied`              | CLI `remediation promotion demote`                           |
| init            | `promotion.init.applied`                | CLI `remediation promotion init` on a fresh environment      |
| reconcile       | `promotion.reconcile.completed`         | CLI `remediation promotion reconcile` after chain replay     |

Total vocabulary: **20 actions** (11 remediation + 9 promotion). Every
payload includes the artifact's `correlation_id` (when applicable) so
operators can join an audit chain to a `RemediationFinding` via that ID.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from charter.audit import AuditEntry, AuditLog

from remediation.promotion.events import (
    ACTION_PROMOTION_ADVANCE_APPLIED,
    ACTION_PROMOTION_ADVANCE_PROPOSED,
    ACTION_PROMOTION_DEMOTE_APPLIED,
    ACTION_PROMOTION_EVIDENCE_STAGE1,
    ACTION_PROMOTION_EVIDENCE_STAGE2,
    ACTION_PROMOTION_EVIDENCE_STAGE3,
    ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
    ACTION_PROMOTION_INIT_APPLIED,
    ACTION_PROMOTION_RECONCILE_COMPLETED,
    PROMOTION_ACTIONS,
)
from remediation.promotion.schemas import PromotionSignOff
from remediation.promotion.tracker import PromotionProposal
from remediation.schemas import (
    RemediationActionType,
    RemediationArtifact,
    RemediationMode,
    RemediationOutcome,
)
from remediation.tools.kubectl_executor import PatchResult
from remediation.validator import ValidationResult

# Centralised action-name vocabulary — keep in sync with the table above.
ACTION_RUN_STARTED = "remediation.run_started"
ACTION_FINDINGS_INGESTED = "remediation.findings_ingested"
ACTION_ACTION_REFUSED = "remediation.action_refused"
ACTION_BLAST_RADIUS_REFUSED = "remediation.blast_radius_refused"
ACTION_ARTIFACT_GENERATED = "remediation.artifact_generated"
ACTION_DRY_RUN_COMPLETED = "remediation.dry_run_completed"
ACTION_EXECUTE_COMPLETED = "remediation.execute_completed"
ACTION_EXECUTE_FAILED = "remediation.execute_failed"
ACTION_VALIDATE_COMPLETED = "remediation.validate_completed"
ACTION_ROLLBACK_COMPLETED = "remediation.rollback_completed"
ACTION_RUN_COMPLETED = "remediation.run_completed"


# The 4 evidence events are the only ones `record_promotion_evidence`
# accepts. Transition events (advance/demote/init/proposed/reconcile)
# belong to dedicated methods on the auditor — see the table above.
_EVIDENCE_EVENT_NAMES: frozenset[str] = frozenset(
    {
        ACTION_PROMOTION_EVIDENCE_STAGE1,
        ACTION_PROMOTION_EVIDENCE_STAGE2,
        ACTION_PROMOTION_EVIDENCE_STAGE3,
        ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
    }
)


def _artifact_handle(artifact: RemediationArtifact) -> dict[str, Any]:
    """Minimal artifact identity for the audit payload.

    We don't emit the full `patch_body` — that's already on the
    `RemediationFinding` in `findings.json`. The audit chain is for
    *what happened*, not *what was patched*; cross-reference via
    `correlation_id`.
    """
    return {
        "action_type": artifact.action_type.value,
        "kind": artifact.kind,
        "namespace": artifact.namespace,
        "name": artifact.name,
        "source_finding_uid": artifact.source_finding_uid,
        "correlation_id": artifact.correlation_id,
    }


def _patch_result_summary(result: PatchResult) -> dict[str, Any]:
    """Audit-side summary of a kubectl-patch result.

    Carries the pre/post-patch hashes for tamper-evident chain proof.
    `stderr` is included (truncated to first 500 chars) so operators can
    investigate failures without re-running.
    """
    return {
        "exit_code": result.exit_code,
        "succeeded": result.succeeded,
        "dry_run": result.dry_run,
        "pre_patch_hash": result.pre_patch_hash,
        "post_patch_hash": result.post_patch_hash,
        "stderr_head": result.stderr[:500] if result.stderr else "",
    }


class PipelineAuditor:
    """Per-run F.6 audit-chain writer for the A.1 7-stage pipeline.

    The driver (Task 12) constructs one of these per agent.run() call,
    using the Charter-owned workspace path (so audit.jsonl lands in the
    run's workspace dir).

    Every method appends one entry to the F.6 hash chain. Entries are
    deterministic given their inputs; the audit chain catches any
    out-of-order or tampered entries.
    """

    def __init__(self, path: Path, *, run_id: str) -> None:
        self._log = AuditLog(path, agent="remediation", run_id=run_id)

    @property
    def path(self) -> Path:
        return self._log.path

    @property
    def tail_hash(self) -> str:
        """The audit chain's current tail hash — Task 12 includes this in the
        `remediation.run_completed` payload so operators can verify the chain
        end-to-end."""
        return self._log._tail

    # ---------------------------- run boundary ---------------------------

    def run_started(
        self,
        *,
        mode: RemediationMode,
        findings_path: str,
        authorized_actions: list[str],
        max_actions_per_run: int,
        rollback_window_sec: int,
    ) -> AuditEntry:
        return self._log.append(
            ACTION_RUN_STARTED,
            {
                "mode": mode.value,
                "findings_path": findings_path,
                "authorized_actions": list(authorized_actions),
                "max_actions_per_run": max_actions_per_run,
                "rollback_window_sec": rollback_window_sec,
            },
        )

    def run_completed(
        self,
        *,
        outcome_counts: dict[str, int],
        total_actions: int,
    ) -> AuditEntry:
        return self._log.append(
            ACTION_RUN_COMPLETED,
            {
                "outcome_counts": dict(outcome_counts),
                "total_actions": total_actions,
            },
        )

    # ---------------------------- Stage 1 --------------------------------

    def findings_ingested(self, *, count: int, source_path: str) -> AuditEntry:
        return self._log.append(
            ACTION_FINDINGS_INGESTED,
            {"count": count, "source_path": source_path},
        )

    # ---------------------------- Stage 2 --------------------------------

    def action_refused(self, *, rule_id: str, reason: str) -> AuditEntry:
        return self._log.append(
            ACTION_ACTION_REFUSED,
            {
                "rule_id": rule_id,
                "reason": reason,
                "outcome": RemediationOutcome.REFUSED_UNAUTHORIZED.value,
            },
        )

    def blast_radius_refused(self, *, requested: int, cap: int) -> AuditEntry:
        return self._log.append(
            ACTION_BLAST_RADIUS_REFUSED,
            {
                "requested_actions": requested,
                "max_actions_per_run": cap,
                "outcome": RemediationOutcome.REFUSED_BLAST_RADIUS.value,
            },
        )

    # ---------------------------- Stage 3 --------------------------------

    def artifact_generated(self, artifact: RemediationArtifact) -> AuditEntry:
        return self._log.append(
            ACTION_ARTIFACT_GENERATED,
            _artifact_handle(artifact),
        )

    # ---------------------------- Stage 4 --------------------------------

    def dry_run_completed(
        self,
        artifact: RemediationArtifact,
        result: PatchResult,
    ) -> AuditEntry:
        payload = _artifact_handle(artifact)
        payload.update(_patch_result_summary(result))
        outcome = (
            RemediationOutcome.DRY_RUN_ONLY
            if result.succeeded
            else RemediationOutcome.DRY_RUN_FAILED
        )
        payload["outcome"] = outcome.value
        return self._log.append(ACTION_DRY_RUN_COMPLETED, payload)

    # ---------------------------- Stage 5 --------------------------------

    def execute_completed(
        self,
        artifact: RemediationArtifact,
        result: PatchResult,
    ) -> AuditEntry:
        payload = _artifact_handle(artifact)
        payload.update(_patch_result_summary(result))
        # Stage 5 leaves the outcome `pending` — Stage 6 sets it to
        # EXECUTED_VALIDATED or EXECUTED_ROLLED_BACK. The audit entry
        # records the patch landed, not the final disposition.
        payload["outcome"] = "pending_validation"
        return self._log.append(ACTION_EXECUTE_COMPLETED, payload)

    def execute_failed(
        self,
        artifact: RemediationArtifact,
        result: PatchResult,
    ) -> AuditEntry:
        payload = _artifact_handle(artifact)
        payload.update(_patch_result_summary(result))
        payload["outcome"] = RemediationOutcome.EXECUTE_FAILED.value
        return self._log.append(ACTION_EXECUTE_FAILED, payload)

    # ---------------------------- Stage 6 --------------------------------

    def validate_completed(
        self,
        artifact: RemediationArtifact,
        validation: ValidationResult,
    ) -> AuditEntry:
        outcome = (
            RemediationOutcome.EXECUTED_ROLLED_BACK
            if validation.requires_rollback
            else RemediationOutcome.EXECUTED_VALIDATED
        )
        payload = _artifact_handle(artifact)
        payload.update(
            {
                "requires_rollback": validation.requires_rollback,
                "matched_findings_count": len(validation.matched_findings),
                "outcome": outcome.value,
            }
        )
        return self._log.append(ACTION_VALIDATE_COMPLETED, payload)

    # ---------------------------- Stage 7 --------------------------------

    def rollback_completed(
        self,
        artifact: RemediationArtifact,
        result: PatchResult,
    ) -> AuditEntry:
        payload = _artifact_handle(artifact)
        payload.update(_patch_result_summary(result))
        payload["outcome"] = RemediationOutcome.EXECUTED_ROLLED_BACK.value
        return self._log.append(ACTION_ROLLBACK_COMPLETED, payload)

    # ---------------------------- promotion (v0.1.1) ---------------------
    #
    # 5 methods covering the 9 `promotion.*` events. Per safety-verification
    # §3, the F.6 audit chain is the source of truth for promotion state;
    # `promotion.yaml` is a derived cache rebuilt from chain replay (Task 6).
    # Every promotion-affecting operation MUST emit through one of these
    # methods — otherwise the state file and the chain drift.

    def record_promotion_evidence(
        self,
        action_type: RemediationActionType,
        *,
        event: str,
        workload: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEntry:
        """Emit one of the 4 evidence events for an action class.

        Args:
            action_type: which remediation action class the evidence is for.
            event: one of the 4 `ACTION_PROMOTION_EVIDENCE_*` constants.
                Transition events (advance/demote/init/proposed/reconcile)
                are rejected — those use dedicated methods.
            workload: required for `stage3` events (the
                `"<namespace>/<workload_name>"` identifier the action acted
                on). The reconciler relies on this field to rebuild
                `stage3_distinct_workloads`.
            correlation_id: optional pointer back to the originating
                `RemediationArtifact`. Lets operators join an evidence event
                to the underlying finding via F.6 5-axis query.

        Raises:
            ValueError: `event` is not one of the 4 evidence constants,
                or `event == ACTION_PROMOTION_EVIDENCE_STAGE3` but
                `workload` is None.
        """
        if event not in _EVIDENCE_EVENT_NAMES:
            raise ValueError(
                f"unknown evidence event {event!r}; expected one of "
                f"{sorted(_EVIDENCE_EVENT_NAMES)} "
                f"(transition events use dedicated record_promotion_* methods)"
            )
        if event == ACTION_PROMOTION_EVIDENCE_STAGE3 and (workload is None or not workload.strip()):
            raise ValueError(
                f"workload is required for {event!r} events "
                f"(populates promotion.yaml's stage3_distinct_workloads on replay)"
            )

        payload: dict[str, Any] = {
            "action_type": action_type.value,
            "event": event,
        }
        if workload is not None:
            payload["workload"] = workload
        if correlation_id is not None:
            payload["correlation_id"] = correlation_id
        return self._log.append(event, payload)

    def record_promotion_proposal(self, proposal: PromotionProposal) -> AuditEntry:
        """Emit `promotion.advance.proposed` when criteria for the next stage are met.

        Informational only — the operator applies the actual transition via
        `record_promotion_transition`. The reconciler (Task 6) emits one of
        these per proposal it discovers when replaying the chain.
        """
        return self._log.append(
            ACTION_PROMOTION_ADVANCE_PROPOSED,
            {
                "action_type": proposal.action_type.value,
                "from_stage": int(proposal.from_stage),
                "to_stage": int(proposal.to_stage),
                "reason": proposal.reason,
                "evidence_summary": dict(proposal.evidence_summary),
            },
        )

    def record_promotion_transition(
        self,
        action_type: RemediationActionType,
        signoff: PromotionSignOff,
    ) -> AuditEntry:
        """Emit `promotion.advance.applied` OR `promotion.demote.applied`.

        Dispatches on `signoff.event_kind`. Called by Task 7's CLI advance
        and demote subcommands AFTER the in-memory tracker has been
        updated; the chain entry is the persistence guarantee (the YAML
        save in the CLI is just a cache write).
        """
        action_name = (
            ACTION_PROMOTION_ADVANCE_APPLIED
            if signoff.event_kind == "advance"
            else ACTION_PROMOTION_DEMOTE_APPLIED
        )
        return self._log.append(
            action_name,
            {
                "action_type": action_type.value,
                "event_kind": signoff.event_kind,
                "operator": signoff.operator,
                "timestamp": signoff.timestamp.isoformat(),
                "reason": signoff.reason,
                "from_stage": int(signoff.from_stage),
                "to_stage": int(signoff.to_stage),
            },
        )

    def record_promotion_init(
        self,
        *,
        cluster_id: str,
        action_classes: list[str],
    ) -> AuditEntry:
        """Emit `promotion.init.applied` when the operator initialises a
        fresh `promotion.yaml` in this environment.

        Args:
            cluster_id: the human-readable cluster label from the new file.
            action_classes: the registered action_type values present in the
                init payload (Stage 1 by default for all of them).
        """
        return self._log.append(
            ACTION_PROMOTION_INIT_APPLIED,
            {
                "cluster_id": cluster_id,
                "action_classes": list(action_classes),
                "default_stage": 1,
            },
        )

    def record_promotion_reconcile(
        self,
        *,
        chain_entries_replayed: int,
        state_changes: dict[str, Any],
    ) -> AuditEntry:
        """Emit `promotion.reconcile.completed` after the reconciler (Task 6)
        rebuilds `promotion.yaml` from the audit chain.

        Args:
            chain_entries_replayed: how many `promotion.*` entries the
                reconciler consumed (sanity-check + observability).
            state_changes: dict summarising what changed during the
                reconcile (e.g. `{"runAsNonRoot": {"stage": "2 → 3"}}`).
                Empty when the in-place file already matched the chain.
        """
        return self._log.append(
            ACTION_PROMOTION_RECONCILE_COMPLETED,
            {
                "chain_entries_replayed": chain_entries_replayed,
                "state_changes": dict(state_changes),
            },
        )


def all_action_names() -> tuple[str, ...]:
    """Return the full vocabulary — F.6 5-axis query filters can use this list.

    Combines A.1 v0.1's 11 `remediation.*` actions with A.1 v0.1.1's 9
    `promotion.*` actions for a total of 20. The order is stable so
    downstream consumers can rely on it for documentation generation.
    """
    return (
        ACTION_RUN_STARTED,
        ACTION_FINDINGS_INGESTED,
        ACTION_ACTION_REFUSED,
        ACTION_BLAST_RADIUS_REFUSED,
        ACTION_ARTIFACT_GENERATED,
        ACTION_DRY_RUN_COMPLETED,
        ACTION_EXECUTE_COMPLETED,
        ACTION_EXECUTE_FAILED,
        ACTION_VALIDATE_COMPLETED,
        ACTION_ROLLBACK_COMPLETED,
        ACTION_RUN_COMPLETED,
        ACTION_PROMOTION_EVIDENCE_STAGE1,
        ACTION_PROMOTION_EVIDENCE_STAGE2,
        ACTION_PROMOTION_EVIDENCE_STAGE3,
        ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
        ACTION_PROMOTION_ADVANCE_PROPOSED,
        ACTION_PROMOTION_ADVANCE_APPLIED,
        ACTION_PROMOTION_DEMOTE_APPLIED,
        ACTION_PROMOTION_INIT_APPLIED,
        ACTION_PROMOTION_RECONCILE_COMPLETED,
    )


__all__ = [
    "ACTION_ACTION_REFUSED",
    "ACTION_ARTIFACT_GENERATED",
    "ACTION_BLAST_RADIUS_REFUSED",
    "ACTION_DRY_RUN_COMPLETED",
    "ACTION_EXECUTE_COMPLETED",
    "ACTION_EXECUTE_FAILED",
    "ACTION_FINDINGS_INGESTED",
    "ACTION_PROMOTION_ADVANCE_APPLIED",
    "ACTION_PROMOTION_ADVANCE_PROPOSED",
    "ACTION_PROMOTION_DEMOTE_APPLIED",
    "ACTION_PROMOTION_EVIDENCE_STAGE1",
    "ACTION_PROMOTION_EVIDENCE_STAGE2",
    "ACTION_PROMOTION_EVIDENCE_STAGE3",
    "ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK",
    "ACTION_PROMOTION_INIT_APPLIED",
    "ACTION_PROMOTION_RECONCILE_COMPLETED",
    "ACTION_ROLLBACK_COMPLETED",
    "ACTION_RUN_COMPLETED",
    "ACTION_RUN_STARTED",
    "ACTION_VALIDATE_COMPLETED",
    "PROMOTION_ACTIONS",
    "PipelineAuditor",
    "RemediationActionType",
    "all_action_names",
]
