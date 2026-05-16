"""F.6 hash-chained audit-log wiring for A.1's 7-stage pipeline.

This module is a thin shim over `charter.audit.AuditLog` that defines:

1. The **action-name vocabulary** A.1 emits (`remediation.*`).
2. A small helper, `PipelineAuditor`, that owns the per-run `AuditLog`
   instance and exposes one method per pipeline stage. The driver (Task 12)
   constructs one `PipelineAuditor` per run and calls the methods at each
   stage boundary.

**Why a vocabulary file** — the F.6 5-axis query API (Task 16's runbook
will reference it) filters by `action` strings. Centralising A.1's
strings here means downstream consumers (D.7 cross-incident correlation,
S.1 console replay) can reason about A.1's audit trail without
string-grep guessing.

The 11 action strings v0.1 emits:

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

Every payload includes the artifact's `correlation_id` (when applicable) so
operators can join an audit chain to a `RemediationFinding` via that ID.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from charter.audit import AuditEntry, AuditLog

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


def all_action_names() -> tuple[str, ...]:
    """Return the full vocabulary — F.6 5-axis query filters can use this list."""
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
    )


__all__ = [
    "ACTION_ACTION_REFUSED",
    "ACTION_ARTIFACT_GENERATED",
    "ACTION_BLAST_RADIUS_REFUSED",
    "ACTION_DRY_RUN_COMPLETED",
    "ACTION_EXECUTE_COMPLETED",
    "ACTION_EXECUTE_FAILED",
    "ACTION_FINDINGS_INGESTED",
    "ACTION_ROLLBACK_COMPLETED",
    "ACTION_RUN_COMPLETED",
    "ACTION_RUN_STARTED",
    "ACTION_VALIDATE_COMPLETED",
    "PipelineAuditor",
    "RemediationActionType",
    "all_action_names",
]
