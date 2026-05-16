"""Audit-chain reconciler — rebuild a `PromotionFile` from `promotion.*` events.

The architectural invariant: `promotion.yaml` is a cache, the F.6
hash-chained audit log is the source of truth (safety-verification §3).
`replay()` reads a chain of `AuditEntry` records (oldest-to-newest),
filters to the 9 `promotion.*` events, and produces the canonical
`PromotionFile` for that chain.

Idempotency contract: replaying the same chain twice yields the same
`PromotionFile` (modulo `last_modified_at`). The reconciler is a pure
function over its inputs.

Error contract:

- Non-promotion entries (`remediation.*` and anything else) are filtered
  silently. The reconciler does not require an isolated promotion-only
  stream.
- Missing required fields in payloads (e.g. `action_type` on an evidence
  event, `workload` on a Stage-3 event) raise `ReplayError`. The chain
  shape is the contract Task 4's `record_promotion_*` methods emit; a
  shape violation means the chain was hand-edited or there's a vocabulary
  drift.
- An `advance.applied` or `demote.applied` whose `from_stage` does not
  match the current reconstructed stage raises `ReplayError`. This is a
  chain inconsistency (missing prior transition, duplicate event, or
  corruption) — fail loudly so the operator can investigate via the
  F.6 5-axis query API.

Used by:
- Task 8's `remediation promotion reconcile` CLI (the operator-facing
  entry point — rebuilds `promotion.yaml` from `audit.jsonl`).
- Internal verification tests — the reconciler is the canonical truth
  function against which the tracker's in-memory state is validated.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from charter.audit import AuditEntry

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
from remediation.promotion.schemas import (
    ActionClassPromotion,
    PromotionEvidence,
    PromotionFile,
    PromotionSignOff,
    PromotionStage,
)
from remediation.schemas import RemediationActionType


class ReplayError(RuntimeError):
    """Raised when the audit chain is inconsistent and cannot be replayed.

    Carries enough context (action, action_type, expected vs actual stage)
    for the operator to investigate via `audit-agent query`.
    """


@dataclasses.dataclass
class _ActionState:
    """Mutable per-action-class scratch state during replay.

    Materialised into an `ActionClassPromotion` (Pydantic-validated) when
    the chain is fully consumed.
    """

    stage: PromotionStage = PromotionStage.STAGE_1
    stage1_artifacts: int = 0
    stage2_dry_runs: int = 0
    stage3_executes: int = 0
    stage3_consecutive_executes: int = 0
    stage3_unexpected_rollbacks: int = 0
    stage3_distinct_workloads: set[str] = dataclasses.field(default_factory=set)
    sign_offs: list[PromotionSignOff] = dataclasses.field(default_factory=list)

    def to_promotion(self, action_type: RemediationActionType) -> ActionClassPromotion:
        return ActionClassPromotion(
            action_type=action_type,
            stage=self.stage,
            evidence=PromotionEvidence(
                stage1_artifacts=self.stage1_artifacts,
                stage2_dry_runs=self.stage2_dry_runs,
                stage3_executes=self.stage3_executes,
                stage3_consecutive_executes=self.stage3_consecutive_executes,
                stage3_unexpected_rollbacks=self.stage3_unexpected_rollbacks,
                stage3_distinct_workloads=sorted(self.stage3_distinct_workloads),
            ),
            sign_offs=list(self.sign_offs),
        )


def replay(
    entries: Iterable[AuditEntry],
    *,
    default_cluster_id: str = "default",
    now: datetime | None = None,
) -> PromotionFile:
    """Reconstruct a `PromotionFile` from a chain of `AuditEntry` records.

    Args:
        entries: ordered audit entries (oldest first). Non-promotion entries
            are filtered silently.
        default_cluster_id: used when no `promotion.init.applied` event is in
            the chain. (Reconcile from a slice of the chain that doesn't
            contain init is a valid use case — the slice has whatever
            entries the operator passed in.)
        now: timestamp for `last_modified_at` on the produced file. Defaults
            to current UTC.

    Returns:
        The canonical `PromotionFile` for the chain.

    Raises:
        ReplayError: chain is inconsistent or malformed.
    """
    now = now or datetime.now(UTC)
    cluster_id = default_cluster_id
    created_at: datetime | None = None
    state: dict[str, _ActionState] = {}
    replayed_count = 0

    for entry in entries:
        if entry.action not in PROMOTION_ACTIONS:
            continue
        replayed_count += 1
        _apply_event(entry, state)
        if entry.action == ACTION_PROMOTION_INIT_APPLIED:
            payload_cluster_id = entry.payload.get("cluster_id")
            if isinstance(payload_cluster_id, str) and payload_cluster_id:
                cluster_id = payload_cluster_id
            if created_at is None:
                created_at = _parse_entry_timestamp(entry)

    return _build_promotion_file(
        state=state,
        cluster_id=cluster_id,
        created_at=created_at or now,
        last_modified_at=now,
    )


def _apply_event(entry: AuditEntry, state: dict[str, _ActionState]) -> None:
    """Dispatch one chain entry to the appropriate state mutation."""
    action = entry.action
    payload = entry.payload

    # Informational events have no state side-effect.
    if action in (ACTION_PROMOTION_ADVANCE_PROPOSED, ACTION_PROMOTION_RECONCILE_COMPLETED):
        return

    if action == ACTION_PROMOTION_INIT_APPLIED:
        # Init resets per-action state. Pre-register the listed action
        # classes at Stage 1 so a subsequent advance.applied has the right
        # current stage. Any pre-existing state is discarded — init is
        # a checkpoint, not a no-op.
        state.clear()
        for ac_str in payload.get("action_classes", []) or []:
            if isinstance(ac_str, str):
                state[ac_str] = _ActionState()
        return

    # All remaining events are per-action-class.
    action_type_str = payload.get("action_type")
    if not isinstance(action_type_str, str):
        raise ReplayError(f"entry {action!r} missing required `action_type` in payload")

    if action_type_str not in state:
        state[action_type_str] = _ActionState()
    s = state[action_type_str]

    if action == ACTION_PROMOTION_EVIDENCE_STAGE1:
        s.stage1_artifacts += 1
    elif action == ACTION_PROMOTION_EVIDENCE_STAGE2:
        s.stage2_dry_runs += 1
    elif action == ACTION_PROMOTION_EVIDENCE_STAGE3:
        workload = payload.get("workload")
        if not isinstance(workload, str) or not workload.strip():
            raise ReplayError(
                f"stage3 evidence event for {action_type_str!r} is missing the "
                f"required `workload` field in its payload"
            )
        s.stage3_executes += 1
        s.stage3_consecutive_executes += 1
        s.stage3_distinct_workloads.add(workload)
    elif action == ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK:
        # An unexpected rollback breaks the consecutive run but does NOT
        # bump stage3_executes (the schema treats them as independent
        # counters; see PromotionEvidence._evidence_invariants).
        s.stage3_consecutive_executes = 0
        s.stage3_unexpected_rollbacks += 1
    elif action in (ACTION_PROMOTION_ADVANCE_APPLIED, ACTION_PROMOTION_DEMOTE_APPLIED):
        signoff = _signoff_from_payload(payload)
        if signoff.from_stage != s.stage:
            raise ReplayError(
                f"chain inconsistency for {action_type_str!r}: {action} expects "
                f"from_stage={int(signoff.from_stage)} but the reconstructed state "
                f"has stage={int(s.stage)}. This usually means a prior transition "
                f"was dropped from the chain, or the chain has been hand-edited. "
                f"Investigate via `audit-agent query --action {action} --action_type "
                f"{action_type_str}`."
            )
        s.sign_offs.append(signoff)
        s.stage = signoff.to_stage
    # No other PROMOTION_ACTIONS members exist — defensive default not needed.


def _signoff_from_payload(payload: dict[str, Any]) -> PromotionSignOff:
    """Reconstruct a `PromotionSignOff` from an advance/demote payload.

    Pydantic validates `event_kind == 'advance'` requires `to_stage == from_stage + 1`;
    `event_kind == 'demote'` requires `to_stage < from_stage`; both reject no-ops.
    A chain that violates these constraints raises a Pydantic
    `ValidationError`, which propagates up as a (deliberately) less-specific
    error than `ReplayError` — the underlying schema is the source of truth
    for what transitions are well-formed.
    """
    required = ("event_kind", "operator", "timestamp", "reason", "from_stage", "to_stage")
    for field in required:
        if field not in payload:
            raise ReplayError(f"sign-off event missing required field {field!r}: {payload!r}")
    return PromotionSignOff(
        event_kind=payload["event_kind"],
        operator=str(payload["operator"]),
        timestamp=_parse_iso(str(payload["timestamp"])),
        reason=str(payload["reason"]),
        from_stage=PromotionStage(int(payload["from_stage"])),
        to_stage=PromotionStage(int(payload["to_stage"])),
    )


def _build_promotion_file(
    *,
    state: dict[str, _ActionState],
    cluster_id: str,
    created_at: datetime,
    last_modified_at: datetime,
) -> PromotionFile:
    """Materialise the scratch state into a Pydantic-validated `PromotionFile`."""
    action_classes: dict[str, ActionClassPromotion] = {}
    for action_type_str, action_state in state.items():
        try:
            action_type = RemediationActionType(action_type_str)
        except ValueError as exc:
            raise ReplayError(
                f"unknown action_type {action_type_str!r} in chain; "
                f"this is a vocabulary drift between the chain producer and "
                f"the current `RemediationActionType` enum"
            ) from exc
        action_classes[action_type_str] = action_state.to_promotion(action_type)

    # last_modified_at must be >= created_at by schema invariant.
    if last_modified_at < created_at:
        last_modified_at = created_at

    return PromotionFile(
        cluster_id=cluster_id,
        created_at=created_at,
        last_modified_at=last_modified_at,
        action_classes=action_classes,
    )


def _parse_iso(value: str) -> datetime:
    """Parse an ISO 8601 datetime string with either `Z` or `+00:00` suffix.

    Charter's `AuditLog` writes the chain timestamp with `Z`; Pydantic's
    `PromotionSignOff` serialises the in-payload timestamp with `+00:00`.
    Handle both for resilience.
    """
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_entry_timestamp(entry: AuditEntry) -> datetime:
    """Parse the AuditEntry's `timestamp` field (string)."""
    return _parse_iso(entry.timestamp)


__all__ = ["ReplayError", "replay"]
