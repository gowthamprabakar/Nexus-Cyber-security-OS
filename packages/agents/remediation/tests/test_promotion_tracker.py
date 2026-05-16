"""Task 3 tracker tests for `remediation.promotion.tracker`.

Covers:

- Load semantics (`from_path` missing-file safe-by-default; valid file
  round-trips; invalid file rejected with a clear error).
- `empty()` factory + the in-memory-only path.
- `save()` atomic write + last_modified_at advancement + tempfile cleanup
  on error.
- `stage_for()` defaults to Stage 1 for untracked action types.
- `record_evidence()` per-event semantics: counter increment, workload
  set growth, consecutive-execute reset on unexpected rollback.
- `record_evidence()` rejects unknown events + transition events + missing
  workload for Stage-3 events.
- `propose_promotions()` Stage 1 → 2 / Stage 2 → 3 / Stage 3 → 4 criteria;
  no-proposal cases; ordering; Stage 4 produces no further proposals.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from remediation.promotion.events import (
    ACTION_PROMOTION_ADVANCE_APPLIED,
    ACTION_PROMOTION_EVIDENCE_STAGE1,
    ACTION_PROMOTION_EVIDENCE_STAGE2,
    ACTION_PROMOTION_EVIDENCE_STAGE3,
    ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
)
from remediation.promotion.schemas import (
    ActionClassPromotion,
    PromotionEvidence,
    PromotionFile,
    PromotionSignOff,
    PromotionStage,
)
from remediation.promotion.tracker import (
    PromotionGateError,
    PromotionProposal,
    PromotionTracker,
)
from remediation.schemas import RemediationActionType

_NOW = datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


# ---------------------------- factory + loader ---------------------------


def test_from_path_returns_none_when_file_missing(tmp_path: Path) -> None:
    """Safe-by-default: a missing file is a valid state meaning "no
    promotions tracked yet" — the driver treats it as all-Stage-1."""
    assert PromotionTracker.from_path(tmp_path / "does_not_exist.yaml") is None


def test_from_path_loads_valid_file(tmp_path: Path) -> None:
    """A valid file round-trips through save → from_path with no loss."""
    p = tmp_path / "promotion.yaml"
    tracker = PromotionTracker.empty(cluster_id="prod-eu-1")
    tracker.save(p)

    loaded = PromotionTracker.from_path(p)
    assert loaded is not None
    assert loaded.file.cluster_id == "prod-eu-1"
    assert loaded.file.schema_version == "0.1"


def test_from_path_rejects_invalid_yaml(tmp_path: Path) -> None:
    """Invalid Pydantic input raises ValidationError so operators see the
    problem at load time rather than silently defaulting to Stage 1."""
    p = tmp_path / "promotion.yaml"
    p.write_text("schema_version: 0.99\ncluster_id: x\n")  # bad schema version

    with pytest.raises(ValidationError):
        PromotionTracker.from_path(p)


def test_empty_factory_starts_with_no_action_classes() -> None:
    """A fresh tracker has zero tracked action classes — every stage_for
    lookup defaults to Stage 1."""
    tracker = PromotionTracker.empty(cluster_id="dev-local")
    assert tracker.file.cluster_id == "dev-local"
    assert tracker.file.action_classes == {}
    assert (
        tracker.stage_for(RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT) is PromotionStage.STAGE_1
    )


# ---------------------------- save -------------------------------------


def test_save_writes_valid_yaml(tmp_path: Path) -> None:
    """The written file round-trips through PromotionFile.model_validate."""
    p = tmp_path / "promotion.yaml"
    tracker = PromotionTracker.empty(cluster_id="prod-eu-1")
    tracker.save(p)

    assert p.exists()
    payload = yaml.safe_load(p.read_text(encoding="utf-8"))
    PromotionFile.model_validate(payload)  # raises if shape is wrong


def test_save_advances_last_modified_at(tmp_path: Path) -> None:
    """Every save bumps `last_modified_at` to current UTC."""
    p = tmp_path / "promotion.yaml"
    tracker = PromotionTracker.empty(cluster_id="x")
    before = tracker.file.last_modified_at

    tracker.save(p)
    after = tracker.file.last_modified_at

    assert after >= before
    assert after.tzinfo is UTC


def test_save_is_atomic_via_tempfile_replace(tmp_path: Path) -> None:
    """The save leaves only the target file in the directory (no `.tmp`
    artifacts after a clean save)."""
    p = tmp_path / "promotion.yaml"
    tracker = PromotionTracker.empty(cluster_id="x")
    tracker.save(p)

    siblings = list(tmp_path.iterdir())
    assert siblings == [p], f"unexpected tempfile artifacts: {siblings}"


def test_save_creates_parent_directory(tmp_path: Path) -> None:
    """The atomic write creates a missing parent dir (mirrors AuditLog)."""
    nested = tmp_path / "deep" / "nested" / "promotion.yaml"
    tracker = PromotionTracker.empty(cluster_id="x")
    tracker.save(nested)

    assert nested.exists()


# ---------------------------- stage_for --------------------------------


def test_stage_for_untracked_action_type_defaults_to_stage_1() -> None:
    """The safe-by-default contract: unlisted action types are at Stage 1."""
    tracker = PromotionTracker.empty()
    for action_type in RemediationActionType:
        assert tracker.stage_for(action_type) is PromotionStage.STAGE_1


def test_stage_for_returns_stored_stage() -> None:
    """A tracked action class returns whatever stage the file pins."""
    signoff = PromotionSignOff(
        event_kind="advance",
        operator="alice",
        timestamp=_NOW,
        reason="dry-runs passed",
        from_stage=PromotionStage.STAGE_1,
        to_stage=PromotionStage.STAGE_2,
    )
    promotion = ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        stage=PromotionStage.STAGE_2,
        sign_offs=[signoff],
    )
    pfile = PromotionFile(
        cluster_id="x",
        created_at=_NOW,
        last_modified_at=_NOW,
        action_classes={"remediation_k8s_patch_runAsNonRoot": promotion},
    )
    tracker = PromotionTracker(pfile)

    assert (
        tracker.stage_for(RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT) is PromotionStage.STAGE_2
    )
    # Other action types still default to Stage 1.
    assert (
        tracker.stage_for(RemediationActionType.K8S_PATCH_RESOURCE_LIMITS) is PromotionStage.STAGE_1
    )


# ---------------------------- record_evidence --------------------------


def test_record_evidence_stage1_increments_only_stage1_counter() -> None:
    """A Stage-1 event bumps stage1_artifacts and nothing else."""
    tracker = PromotionTracker.empty()
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )

    entry = tracker.file.action_classes["remediation_k8s_patch_runAsNonRoot"]
    assert entry.evidence.stage1_artifacts == 1
    assert entry.evidence.stage2_dry_runs == 0
    assert entry.evidence.stage3_executes == 0
    assert entry.evidence.stage3_unexpected_rollbacks == 0


def test_record_evidence_stage2_increments_only_dry_runs() -> None:
    tracker = PromotionTracker.empty()
    for _ in range(3):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE2,
        )

    entry = tracker.file.action_classes["remediation_k8s_patch_runAsNonRoot"]
    assert entry.evidence.stage2_dry_runs == 3
    assert entry.evidence.stage1_artifacts == 0
    assert entry.evidence.stage3_executes == 0


def test_record_evidence_stage3_increments_total_consecutive_and_workload_set() -> None:
    """A Stage-3 event bumps both counters and adds the workload to the
    distinct-workload set."""
    tracker = PromotionTracker.empty()
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE3,
        workload="production/api",
    )
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE3,
        workload="production/web",
    )
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE3,
        workload="production/api",  # duplicate — dedup
    )

    ev = tracker.file.action_classes["remediation_k8s_patch_runAsNonRoot"].evidence
    assert ev.stage3_executes == 3
    assert ev.stage3_consecutive_executes == 3
    assert ev.stage3_distinct_workloads == ["production/api", "production/web"]


def test_record_evidence_unexpected_rollback_resets_consecutive() -> None:
    """An unexpected rollback zeroes the consecutive counter (the chain
    breaks) and bumps the rollback counter."""
    tracker = PromotionTracker.empty()
    for i in range(5):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=f"production/app-{i}",
        )
    # 5 consecutive successes so far.
    ev = tracker.file.action_classes["remediation_k8s_patch_runAsNonRoot"].evidence
    assert ev.stage3_consecutive_executes == 5

    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
    )
    # Consecutive resets; total stays.
    ev = tracker.file.action_classes["remediation_k8s_patch_runAsNonRoot"].evidence
    assert ev.stage3_consecutive_executes == 0
    assert ev.stage3_executes == 5
    assert ev.stage3_unexpected_rollbacks == 1


def test_record_evidence_for_unknown_action_type_creates_entry_at_stage_1() -> None:
    """A previously-untracked action class is registered at Stage 1 when
    the first evidence event fires."""
    tracker = PromotionTracker.empty()
    assert "remediation_k8s_patch_imagePullPolicy_Always" not in tracker.file.action_classes

    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )
    entry = tracker.file.action_classes["remediation_k8s_patch_imagePullPolicy_Always"]
    assert entry.stage is PromotionStage.STAGE_1
    assert entry.evidence.stage1_artifacts == 1


def test_record_evidence_rejects_unknown_event() -> None:
    """Garbage event strings raise ValueError."""
    tracker = PromotionTracker.empty()
    with pytest.raises(ValueError, match="unknown evidence event"):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event="not.a.real.event",
        )


def test_record_evidence_rejects_transition_events() -> None:
    """Transition events (advance/demote/init/proposed/reconcile) are NOT
    evidence — they belong to the operator CLI surface."""
    tracker = PromotionTracker.empty()
    with pytest.raises(ValueError, match="unknown evidence event"):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_ADVANCE_APPLIED,
        )


def test_record_evidence_stage3_requires_workload() -> None:
    """Stage-3 events without a workload identifier are rejected — the
    distinct-workloads counter is the load-bearing Stage-4 criterion."""
    tracker = PromotionTracker.empty()
    with pytest.raises(ValueError, match="workload is required"):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=None,
        )
    with pytest.raises(ValueError, match="workload is required"):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload="   ",  # whitespace counts as missing
        )


# ---------------------------- propose_promotions -----------------------


def test_propose_promotions_empty_for_fresh_tracker() -> None:
    """No evidence yet → no proposals."""
    tracker = PromotionTracker.empty()
    assert tracker.propose_promotions() == []


def test_propose_promotions_stage1_to_2_after_first_artifact() -> None:
    """Stage 1 → 2 proposal fires as soon as ≥1 stage1_artifact exists."""
    tracker = PromotionTracker.empty()
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )
    proposals = tracker.propose_promotions()
    assert len(proposals) == 1
    p = proposals[0]
    assert p.from_stage is PromotionStage.STAGE_1
    assert p.to_stage is PromotionStage.STAGE_2
    assert "operator confirms" in p.reason


def test_propose_promotions_stage2_to_3_requires_five_dry_runs() -> None:
    """Stage 2 → 3 fires at 5 dry-runs; 4 is not enough."""
    tracker = _tracker_with_action_at_stage_2()
    for _ in range(4):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE2,
        )
    assert tracker.propose_promotions() == []  # 4 < 5

    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE2,
    )
    proposals = tracker.propose_promotions()
    assert len(proposals) == 1
    assert proposals[0].from_stage is PromotionStage.STAGE_2
    assert proposals[0].to_stage is PromotionStage.STAGE_3


def test_propose_promotions_stage3_to_4_requires_both_thresholds() -> None:
    """Stage 3 → 4 needs ≥30 consecutive AND ≥10 distinct workloads."""
    # Stage 3 with 30 consecutive but only 5 distinct workloads — NOT enough.
    tracker = _tracker_with_action_at_stage_3()
    for i in range(30):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=f"production/app-{i % 5}",  # only 5 distinct
        )
    assert tracker.propose_promotions() == []

    # Add 5 more distinct workloads (still extends consecutive run).
    for i in range(5, 10):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=f"production/app-{i}",
        )
    proposals = tracker.propose_promotions()
    assert len(proposals) == 1
    assert proposals[0].from_stage is PromotionStage.STAGE_3
    assert proposals[0].to_stage is PromotionStage.STAGE_4
    # The reason text names the security-lead + global-gate requirement.
    assert "security-lead sign-off" in proposals[0].reason.lower()
    assert "stage-4 global gate" in proposals[0].reason.lower()


def test_propose_promotions_stage3_to_4_blocked_by_consecutive_break() -> None:
    """An unexpected rollback resets consecutive → proposal gone."""
    tracker = _tracker_with_action_at_stage_3()
    for i in range(30):
        tracker.record_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=f"production/app-{i}",
        )
    # 30 consecutive + 30 distinct → proposal exists.
    assert len(tracker.propose_promotions()) == 1

    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
    )
    # Consecutive resets to 0 → proposal gone.
    assert tracker.propose_promotions() == []


def test_propose_promotions_stage4_is_top_no_further_proposals() -> None:
    """Stage 4 is the highest stage; the tracker proposes nothing above it."""
    signoffs = [
        PromotionSignOff(
            event_kind="advance",
            operator="alice",
            timestamp=_NOW,
            reason="x",
            from_stage=PromotionStage.STAGE_1,
            to_stage=PromotionStage.STAGE_2,
        ),
        PromotionSignOff(
            event_kind="advance",
            operator="alice",
            timestamp=_NOW,
            reason="y",
            from_stage=PromotionStage.STAGE_2,
            to_stage=PromotionStage.STAGE_3,
        ),
        PromotionSignOff(
            event_kind="advance",
            operator="alice",
            timestamp=_NOW,
            reason="z",
            from_stage=PromotionStage.STAGE_3,
            to_stage=PromotionStage.STAGE_4,
        ),
    ]
    promotion = ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        stage=PromotionStage.STAGE_4,
        evidence=PromotionEvidence(
            stage3_executes=100,
            stage3_consecutive_executes=100,
            stage3_distinct_workloads=[f"prod/app-{i}" for i in range(50)],
        ),
        sign_offs=signoffs,
    )
    pfile = PromotionFile(
        cluster_id="x",
        created_at=_NOW,
        last_modified_at=_NOW,
        action_classes={"remediation_k8s_patch_runAsNonRoot": promotion},
    )
    tracker = PromotionTracker(pfile)

    assert tracker.propose_promotions() == []


def test_propose_promotions_returns_one_per_eligible_action_class() -> None:
    """Multiple action classes can each generate a proposal independently."""
    tracker = PromotionTracker.empty()
    # Action A: at Stage 1 with artifacts → propose →2.
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )
    # Action B: at Stage 1 with artifacts → propose →2.
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )

    proposals = tracker.propose_promotions()
    action_types = {p.action_type for p in proposals}
    assert action_types == {
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        RemediationActionType.K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS,
    }
    assert all(p.to_stage is PromotionStage.STAGE_2 for p in proposals)


# ---------------------------- round-trip persistence -------------------


def test_record_then_save_then_load_preserves_state(tmp_path: Path) -> None:
    """A tracker mutated via record_evidence, saved, and reloaded matches
    the in-memory tracker bit-for-bit on the load_path."""
    p = tmp_path / "promotion.yaml"
    tracker = PromotionTracker.empty(cluster_id="prod-eu-1")
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE2,
    )
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE2,
    )
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RESOURCE_LIMITS,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )
    tracker.save(p)

    reloaded = PromotionTracker.from_path(p)
    assert reloaded is not None
    assert reloaded.file.cluster_id == "prod-eu-1"
    assert len(reloaded.file.action_classes) == 2
    run_as_root = reloaded.file.action_classes["remediation_k8s_patch_runAsNonRoot"]
    assert run_as_root.evidence.stage2_dry_runs == 2
    res_limits = reloaded.file.action_classes["remediation_k8s_patch_resource_limits"]
    assert res_limits.evidence.stage1_artifacts == 1


# ---------------------------- exception surface ------------------------


def test_promotion_gate_error_is_runtime_error_subclass() -> None:
    """PromotionGateError remains catchable as RuntimeError for callers
    that already handle the broader category (e.g. driver wrapping)."""
    assert issubclass(PromotionGateError, RuntimeError)


def test_promotion_proposal_is_frozen_dataclass() -> None:
    """PromotionProposal is hashable + immutable so it can flow through
    sets/dict keys for diff-style reconciliation."""
    p = PromotionProposal(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        from_stage=PromotionStage.STAGE_1,
        to_stage=PromotionStage.STAGE_2,
        reason="x",
        evidence_summary={"stage1_artifacts": 1},
    )
    # Frozen dataclass raises `dataclasses.FrozenInstanceError` on assignment.
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.reason = "mutated"  # type: ignore[misc]


# ---------------------------- helpers ----------------------------------


def _tracker_with_action_at_stage_2() -> PromotionTracker:
    """Build a tracker with the run-as-non-root action class at Stage 2 +
    one prior sign-off, so propose_promotions() can grade Stage 2 → 3."""
    signoff = PromotionSignOff(
        event_kind="advance",
        operator="alice",
        timestamp=_NOW,
        reason="initial",
        from_stage=PromotionStage.STAGE_1,
        to_stage=PromotionStage.STAGE_2,
    )
    promotion = ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        stage=PromotionStage.STAGE_2,
        sign_offs=[signoff],
    )
    pfile = PromotionFile(
        cluster_id="x",
        created_at=_NOW,
        last_modified_at=_NOW,
        action_classes={"remediation_k8s_patch_runAsNonRoot": promotion},
    )
    return PromotionTracker(pfile)


def _tracker_with_action_at_stage_3() -> PromotionTracker:
    """Build a tracker with the run-as-non-root action class at Stage 3 +
    two prior sign-offs, so propose_promotions() can grade Stage 3 → 4."""
    s12 = PromotionSignOff(
        event_kind="advance",
        operator="alice",
        timestamp=_NOW,
        reason="initial",
        from_stage=PromotionStage.STAGE_1,
        to_stage=PromotionStage.STAGE_2,
    )
    s23 = PromotionSignOff(
        event_kind="advance",
        operator="alice",
        timestamp=_NOW,
        reason="dry-runs passed",
        from_stage=PromotionStage.STAGE_2,
        to_stage=PromotionStage.STAGE_3,
    )
    promotion = ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        stage=PromotionStage.STAGE_3,
        sign_offs=[s12, s23],
    )
    pfile = PromotionFile(
        cluster_id="x",
        created_at=_NOW,
        last_modified_at=_NOW,
        action_classes={"remediation_k8s_patch_runAsNonRoot": promotion},
    )
    return PromotionTracker(pfile)
