"""Task 6 reconciler tests for `remediation.promotion.replay`.

The reconciler is the function that makes "F.6 chain is the source of
truth; promotion.yaml is a cache" operationally meaningful: given any
chain, it produces the canonical `PromotionFile` for that chain.

These tests cover:

1. Empty + init-only chains.
2. Per-event-type state mutation (4 evidence events x 2 transition events).
3. Mid-chain demotions (Stage 3 → Stage 1 in one event).
4. Multi-init handling (an init resets the prior state).
5. Stage-3 distinct workload tracking with duplicates.
6. Non-promotion entries filtered silently.
7. Round-trip parity with `PipelineAuditor`: emit a chain via the auditor,
   read it back, replay it, verify equality with a tracker-generated state.
8. Idempotency contract.
9. Error paths: missing `action_type` / missing `workload` / inconsistent
   `from_stage` / unknown action_type strings (vocabulary drift).
10. Informational events (`advance.proposed`, `reconcile.completed`)
    produce zero state change.

Total: 18 tests per the plan task row.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.audit import AuditEntry
from remediation.audit import PipelineAuditor
from remediation.promotion import (
    PromotionFile,
    PromotionSignOff,
    PromotionStage,
    PromotionTracker,
    ReplayError,
    replay,
)
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
)
from remediation.promotion.tracker import PromotionProposal
from remediation.schemas import RemediationActionType

_NOW = datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)
_RUN_AS_ROOT = "remediation_k8s_patch_runAsNonRoot"
_PULL_POLICY = "remediation_k8s_patch_imagePullPolicy_Always"


# ---------------------------- chain builder -----------------------------


def _entry(
    action: str,
    payload: dict[str, Any],
    *,
    when: datetime | None = None,
    run_id: str = "test-run",
) -> AuditEntry:
    """Build a minimal `AuditEntry` for a `promotion.*` event. The replay
    function ignores `previous_hash` / `entry_hash` integrity — those are
    F.6's concern, not the reconciler's."""
    ts = (when or _NOW).isoformat().replace("+00:00", "Z")
    return AuditEntry(
        timestamp=ts,
        agent="remediation",
        run_id=run_id,
        action=action,
        payload=payload,
        previous_hash="x" * 64,
        entry_hash="y" * 64,
    )


def _signoff_payload(
    *,
    event_kind: str,
    from_stage: int,
    to_stage: int,
    operator: str = "alice",
    reason: str = "test transition",
    action_type: str = _RUN_AS_ROOT,
) -> dict[str, Any]:
    return {
        "action_type": action_type,
        "event_kind": event_kind,
        "operator": operator,
        "timestamp": _NOW.isoformat(),
        "reason": reason,
        "from_stage": from_stage,
        "to_stage": to_stage,
    }


# ---------------------------- empty / init-only -------------------------


def test_replay_empty_chain_returns_empty_promotion_file() -> None:
    """No entries → a fresh PromotionFile with no action_classes."""
    result = replay([], default_cluster_id="prod-eu-1", now=_NOW)
    assert isinstance(result, PromotionFile)
    assert result.cluster_id == "prod-eu-1"
    assert result.action_classes == {}
    # created_at defaults to `now` when no init is in the chain.
    assert result.last_modified_at == _NOW


def test_replay_init_only_chain_registers_action_classes_at_stage_1() -> None:
    """An init.applied entry pre-registers action classes at Stage 1."""
    entries = [
        _entry(
            ACTION_PROMOTION_INIT_APPLIED,
            {
                "cluster_id": "prod-eu-1",
                "action_classes": [_RUN_AS_ROOT, _PULL_POLICY],
                "default_stage": 1,
            },
            when=_NOW,
        ),
    ]
    result = replay(entries, now=_NOW + timedelta(seconds=1))
    assert result.cluster_id == "prod-eu-1"
    assert set(result.action_classes.keys()) == {_RUN_AS_ROOT, _PULL_POLICY}
    for entry in result.action_classes.values():
        assert entry.stage is PromotionStage.STAGE_1
        assert entry.evidence.stage1_artifacts == 0
        assert entry.sign_offs == []


# ---------------------------- evidence events ---------------------------


def test_replay_stage1_evidence_increments_counter() -> None:
    entries = [
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE1,
            {"action_type": _RUN_AS_ROOT, "event": ACTION_PROMOTION_EVIDENCE_STAGE1},
        ),
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE1,
            {"action_type": _RUN_AS_ROOT, "event": ACTION_PROMOTION_EVIDENCE_STAGE1},
        ),
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE1,
            {"action_type": _RUN_AS_ROOT, "event": ACTION_PROMOTION_EVIDENCE_STAGE1},
        ),
    ]
    result = replay(entries, now=_NOW)
    entry = result.action_classes[_RUN_AS_ROOT]
    assert entry.evidence.stage1_artifacts == 3
    assert entry.evidence.stage2_dry_runs == 0
    assert entry.evidence.stage3_executes == 0


def test_replay_stage2_evidence_increments_dry_runs() -> None:
    entries = [
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE2,
            {"action_type": _RUN_AS_ROOT, "event": ACTION_PROMOTION_EVIDENCE_STAGE2},
        ),
    ] * 5
    result = replay(entries, now=_NOW)
    assert result.action_classes[_RUN_AS_ROOT].evidence.stage2_dry_runs == 5


def test_replay_stage3_evidence_tracks_total_consecutive_and_workloads() -> None:
    """Stage-3 events bump total + consecutive AND grow the distinct-workload set."""
    entries = [
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE3,
            {
                "action_type": _RUN_AS_ROOT,
                "event": ACTION_PROMOTION_EVIDENCE_STAGE3,
                "workload": f"production/app-{i}",
            },
        )
        for i in range(7)
    ]
    result = replay(entries, now=_NOW)
    ev = result.action_classes[_RUN_AS_ROOT].evidence
    assert ev.stage3_executes == 7
    assert ev.stage3_consecutive_executes == 7
    assert len(ev.stage3_distinct_workloads) == 7


def test_replay_stage3_duplicate_workloads_dedupe() -> None:
    """Duplicate workloads on Stage-3 events get deduped in the final state."""
    entries = [
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE3,
            {
                "action_type": _RUN_AS_ROOT,
                "event": ACTION_PROMOTION_EVIDENCE_STAGE3,
                "workload": "production/api",
            },
        ),
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE3,
            {
                "action_type": _RUN_AS_ROOT,
                "event": ACTION_PROMOTION_EVIDENCE_STAGE3,
                "workload": "production/api",  # duplicate
            },
        ),
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE3,
            {
                "action_type": _RUN_AS_ROOT,
                "event": ACTION_PROMOTION_EVIDENCE_STAGE3,
                "workload": "production/web",
            },
        ),
    ]
    result = replay(entries, now=_NOW)
    ev = result.action_classes[_RUN_AS_ROOT].evidence
    assert ev.stage3_executes == 3  # raw count
    assert ev.stage3_distinct_workloads == ["production/api", "production/web"]


def test_replay_unexpected_rollback_resets_consecutive() -> None:
    """An unexpected_rollback event zeroes consecutive but bumps the
    rollback counter. stage3_executes is NOT bumped (independent counter)."""
    entries = [
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE3,
            {
                "action_type": _RUN_AS_ROOT,
                "event": ACTION_PROMOTION_EVIDENCE_STAGE3,
                "workload": "prod/a",
            },
        ),
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE3,
            {
                "action_type": _RUN_AS_ROOT,
                "event": ACTION_PROMOTION_EVIDENCE_STAGE3,
                "workload": "prod/b",
            },
        ),
        _entry(
            ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
            {
                "action_type": _RUN_AS_ROOT,
                "event": ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
            },
        ),
    ]
    result = replay(entries, now=_NOW)
    ev = result.action_classes[_RUN_AS_ROOT].evidence
    assert ev.stage3_executes == 2
    assert ev.stage3_consecutive_executes == 0
    assert ev.stage3_unexpected_rollbacks == 1


def test_replay_unexpected_rollback_on_fresh_action_class_is_valid() -> None:
    """The bug we fixed: rollback before any validated execute is now a
    valid state. (Earlier schema invariant rejected it.)"""
    entries = [
        _entry(
            ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
            {
                "action_type": _RUN_AS_ROOT,
                "event": ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
            },
        ),
    ]
    result = replay(entries, now=_NOW)
    ev = result.action_classes[_RUN_AS_ROOT].evidence
    assert ev.stage3_executes == 0
    assert ev.stage3_unexpected_rollbacks == 1


# ---------------------------- transition events -------------------------


def test_replay_advance_applied_appends_signoff_and_updates_stage() -> None:
    entries = [
        _entry(
            ACTION_PROMOTION_ADVANCE_APPLIED,
            _signoff_payload(event_kind="advance", from_stage=1, to_stage=2),
        ),
    ]
    result = replay(entries, now=_NOW)
    entry = result.action_classes[_RUN_AS_ROOT]
    assert entry.stage is PromotionStage.STAGE_2
    assert len(entry.sign_offs) == 1
    assert entry.sign_offs[0].event_kind == "advance"
    assert entry.sign_offs[0].from_stage is PromotionStage.STAGE_1
    assert entry.sign_offs[0].to_stage is PromotionStage.STAGE_2


def test_replay_demote_applied_moves_stage_down() -> None:
    """Stage 3 → Stage 1 in one demote event."""
    entries = [
        _entry(
            ACTION_PROMOTION_ADVANCE_APPLIED,
            _signoff_payload(event_kind="advance", from_stage=1, to_stage=2, reason="step 1"),
            when=_NOW,
        ),
        _entry(
            ACTION_PROMOTION_ADVANCE_APPLIED,
            _signoff_payload(
                event_kind="advance",
                from_stage=2,
                to_stage=3,
                reason="step 2",
            ),
            when=_NOW + timedelta(days=7),
        ),
        _entry(
            ACTION_PROMOTION_DEMOTE_APPLIED,
            _signoff_payload(
                event_kind="demote",
                from_stage=3,
                to_stage=1,
                reason="incident #42 — full rollback",
            ),
            when=_NOW + timedelta(days=14),
        ),
    ]
    result = replay(entries, now=_NOW + timedelta(days=15))
    entry = result.action_classes[_RUN_AS_ROOT]
    assert entry.stage is PromotionStage.STAGE_1
    assert len(entry.sign_offs) == 3
    assert entry.sign_offs[-1].event_kind == "demote"


# ---------------------------- multi-init / reset ------------------------


def test_replay_subsequent_init_resets_prior_state() -> None:
    """A second init.applied resets accumulated state — operators use this
    as a checkpoint after disaster recovery."""
    entries = [
        _entry(
            ACTION_PROMOTION_INIT_APPLIED,
            {"cluster_id": "first", "action_classes": [_RUN_AS_ROOT], "default_stage": 1},
        ),
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE2,
            {"action_type": _RUN_AS_ROOT, "event": ACTION_PROMOTION_EVIDENCE_STAGE2},
        ),
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE2,
            {"action_type": _RUN_AS_ROOT, "event": ACTION_PROMOTION_EVIDENCE_STAGE2},
        ),
        _entry(
            ACTION_PROMOTION_INIT_APPLIED,
            {"cluster_id": "second", "action_classes": [_RUN_AS_ROOT], "default_stage": 1},
        ),
    ]
    result = replay(entries, now=_NOW)
    # Second init wiped the stage2_dry_runs accumulation.
    assert result.cluster_id == "second"
    assert result.action_classes[_RUN_AS_ROOT].evidence.stage2_dry_runs == 0


# ---------------------------- informational events ----------------------


def test_replay_proposed_and_reconcile_events_produce_no_state_change() -> None:
    """`promotion.advance.proposed` and `promotion.reconcile.completed` are
    informational — replay should produce zero state change for them."""
    entries = [
        _entry(
            ACTION_PROMOTION_ADVANCE_PROPOSED,
            {
                "action_type": _RUN_AS_ROOT,
                "from_stage": 2,
                "to_stage": 3,
                "reason": "5 dry-runs accumulated",
                "evidence_summary": {"stage2_dry_runs": 5},
            },
        ),
        _entry(
            ACTION_PROMOTION_RECONCILE_COMPLETED,
            {"chain_entries_replayed": 7, "state_changes": {}},
        ),
    ]
    result = replay(entries, now=_NOW)
    assert result.action_classes == {}


# ---------------------------- non-promotion filtering -------------------


def test_replay_filters_non_promotion_entries_silently() -> None:
    """A chain mixing remediation.* and promotion.* entries → only the
    promotion.* events drive state mutation."""
    entries = [
        _entry(
            "remediation.run_started",
            {"mode": "execute", "findings_path": "/x"},
        ),
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE1,
            {"action_type": _RUN_AS_ROOT, "event": ACTION_PROMOTION_EVIDENCE_STAGE1},
        ),
        _entry(
            "remediation.run_completed",
            {"outcome_counts": {"recommended_only": 1}, "total_actions": 1},
        ),
    ]
    result = replay(entries, now=_NOW)
    assert result.action_classes[_RUN_AS_ROOT].evidence.stage1_artifacts == 1


# ---------------------------- error paths -------------------------------


def test_replay_missing_action_type_raises() -> None:
    entries = [
        _entry(ACTION_PROMOTION_EVIDENCE_STAGE1, {"event": ACTION_PROMOTION_EVIDENCE_STAGE1}),
    ]
    with pytest.raises(ReplayError, match="missing required `action_type`"):
        replay(entries, now=_NOW)


def test_replay_stage3_missing_workload_raises() -> None:
    entries = [
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE3,
            {"action_type": _RUN_AS_ROOT, "event": ACTION_PROMOTION_EVIDENCE_STAGE3},
        ),
    ]
    with pytest.raises(ReplayError, match="missing the required `workload`"):
        replay(entries, now=_NOW)


def test_replay_inconsistent_signoff_from_stage_raises() -> None:
    """advance.applied with from_stage that doesn't match current state →
    ReplayError pointing the operator at the F.6 query API."""
    entries = [
        # No prior transitions; state is Stage 1.
        _entry(
            ACTION_PROMOTION_ADVANCE_APPLIED,
            _signoff_payload(event_kind="advance", from_stage=2, to_stage=3),
        ),
    ]
    with pytest.raises(ReplayError, match="chain inconsistency"):
        replay(entries, now=_NOW)


def test_replay_unknown_action_type_raises() -> None:
    """A chain emitted by a future version with a new RemediationActionType
    would be unreadable by this reconciler — fail loudly so operators see
    the vocabulary drift."""
    entries = [
        _entry(
            ACTION_PROMOTION_EVIDENCE_STAGE1,
            {
                "action_type": "remediation_k8s_patch_NewFutureAction",
                "event": ACTION_PROMOTION_EVIDENCE_STAGE1,
            },
        ),
    ]
    with pytest.raises(ReplayError, match="unknown action_type"):
        replay(entries, now=_NOW)


# ---------------------------- round-trip parity --------------------------


def test_replay_round_trip_matches_tracker_state(tmp_path: Path) -> None:
    """Drive a `PromotionTracker` + `PipelineAuditor` through a realistic
    operation sequence; replay the resulting audit chain; assert the
    reconstructed `PromotionFile` matches `tracker.file` field-by-field.

    This is the load-bearing test: it proves the auditor + tracker + replay
    are mutually consistent.
    """
    audit_path = tmp_path / "audit.jsonl"
    auditor = PipelineAuditor(audit_path, run_id="round-trip-run")
    tracker = PromotionTracker.empty(cluster_id="prod-eu-1")

    # Sequence: init + stage1 x3 + advance(1→2) + stage2 x5 + advance(2→3)
    #           + stage3 x4 (workloads a/b/c/d) + unexpected_rollback + stage3 x2 (a, e)
    auditor.record_promotion_init(cluster_id="prod-eu-1", action_classes=[_RUN_AS_ROOT])

    for _ in range(3):
        auditor.record_promotion_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE1,
        )
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE1,
        )

    advance_1_to_2 = PromotionSignOff(
        event_kind="advance",
        operator="alice",
        timestamp=_NOW,
        reason="operator confirmed stage 1 artifacts work",
        from_stage=PromotionStage.STAGE_1,
        to_stage=PromotionStage.STAGE_2,
    )
    auditor.record_promotion_transition(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT, advance_1_to_2
    )
    _apply_signoff_to_tracker(tracker, _RUN_AS_ROOT, advance_1_to_2)

    for _ in range(5):
        auditor.record_promotion_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE2,
        )
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE2,
        )

    advance_2_to_3 = PromotionSignOff(
        event_kind="advance",
        operator="alice",
        timestamp=_NOW + timedelta(days=7),
        reason="5 dry-runs passed",
        from_stage=PromotionStage.STAGE_2,
        to_stage=PromotionStage.STAGE_3,
    )
    auditor.record_promotion_transition(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT, advance_2_to_3
    )
    _apply_signoff_to_tracker(tracker, _RUN_AS_ROOT, advance_2_to_3)

    for wl in ("prod/a", "prod/b", "prod/c", "prod/d"):
        auditor.record_promotion_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=wl,
        )
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=wl,
        )

    auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
    )
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
    )

    for wl in ("prod/a", "prod/e"):  # one duplicate, one new
        auditor.record_promotion_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=wl,
        )
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=wl,
        )

    # Read the chain back from disk + replay.
    chain = _read_chain(audit_path)
    replayed = replay(chain, now=_NOW + timedelta(days=8))

    # Compare to the tracker's in-memory state.
    tracker_entry = tracker.file.action_classes[_RUN_AS_ROOT]
    replayed_entry = replayed.action_classes[_RUN_AS_ROOT]

    assert replayed_entry.stage is tracker_entry.stage
    assert replayed_entry.evidence.model_dump() == tracker_entry.evidence.model_dump()
    # Sign-offs: replayed timestamps round-trip through ISO; tracker uses
    # the original PromotionSignOff instances. Both should serialise to
    # the same JSON.
    tracker_signoffs = [s.model_dump(mode="json") for s in tracker_entry.sign_offs]
    replayed_signoffs = [s.model_dump(mode="json") for s in replayed_entry.sign_offs]
    assert replayed_signoffs == tracker_signoffs


def test_replay_is_idempotent(tmp_path: Path) -> None:
    """Replaying the same chain twice produces the same `PromotionFile`
    (modulo `last_modified_at`, which is set to `now` each call)."""
    audit_path = tmp_path / "audit.jsonl"
    auditor = PipelineAuditor(audit_path, run_id="idempotency-run")
    auditor.record_promotion_init(cluster_id="prod-eu-1", action_classes=[_RUN_AS_ROOT])
    auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )
    auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE2,
    )

    chain = _read_chain(audit_path)

    first = replay(chain, now=_NOW)
    second = replay(chain, now=_NOW)

    # Everything except last_modified_at should be identical.
    first_dump = first.model_dump(mode="json")
    second_dump = second.model_dump(mode="json")
    assert first_dump == second_dump


# ---------------------------- helpers -----------------------------------


def _read_chain(path: Path) -> list[AuditEntry]:
    """Read an `audit.jsonl` file into a list of AuditEntry records."""
    entries: list[AuditEntry] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        entries.append(AuditEntry.from_json(line))
    return entries


def _apply_signoff_to_tracker(
    tracker: PromotionTracker,
    action_type_str: str,
    signoff: PromotionSignOff,
) -> None:
    """Mirror what Task 7's CLI advance/demote will do: append the sign-off
    to the tracker's in-memory state. Encodes the same shape the replay
    function will produce.
    """
    entry = tracker.file.action_classes.get(action_type_str)
    if entry is None:
        raise AssertionError(f"action_class {action_type_str!r} not in tracker")
    # Re-construct the action class with the new sign-off + stage.
    from remediation.promotion import ActionClassPromotion

    new_signoffs = [*entry.sign_offs, signoff]
    tracker.file.action_classes[action_type_str] = ActionClassPromotion(
        action_type=entry.action_type,
        stage=signoff.to_stage,
        evidence=entry.evidence.model_copy(deep=True),
        sign_offs=new_signoffs,
    )


# Touch unused imports so the linter doesn't strip them — these are useful
# for future tests in this file.
_ = json
_ = PromotionProposal
