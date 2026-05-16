"""Task 2 schema tests for `remediation.promotion.schemas`.

Every model in the promotion schema family is exercised here:

- `PromotionStage` — IntEnum behaviour, ordering, value range.
- `stage_max_mode` — the stage → mode mapping the pre-flight gate enforces.
- `PromotionEvidence` — counter non-negativity, cross-field invariants,
  workload de-duplication.
- `PromotionSignOff` — event-kind direction rules, no-op rejection,
  timezone-aware timestamps.
- `ActionClassPromotion` — stage/sign-off consistency, chronological order.
- `PromotionFile` — schema-version pinning, action_classes key validation,
  created/modified invariant.

The full graduation-decision logic ("is the evidence sufficient for the
next stage?") lives in `PromotionTracker.propose_promotions()` (Task 3);
this file covers schema-level invariants only.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from remediation.promotion.schemas import (
    PROMOTION_FILE_SCHEMA_VERSION,
    ActionClassPromotion,
    PromotionEvidence,
    PromotionFile,
    PromotionSignOff,
    PromotionStage,
    stage_max_mode,
)
from remediation.schemas import RemediationActionType, RemediationMode

# ---------------------------- stage enum + mapping -----------------------


def test_promotion_stage_is_int_enum_ordered() -> None:
    """IntEnum with 4 members; less-than comparisons work for `≥ Stage N` checks."""
    assert PromotionStage.STAGE_1 < PromotionStage.STAGE_2
    assert PromotionStage.STAGE_2 < PromotionStage.STAGE_3
    assert PromotionStage.STAGE_3 < PromotionStage.STAGE_4
    assert int(PromotionStage.STAGE_1) == 1
    assert int(PromotionStage.STAGE_4) == 4


def test_promotion_stage_has_exactly_four_members() -> None:
    """The four-stage pipeline is load-bearing — a fifth stage entering by
    accident would silently broaden permissions."""
    assert len(PromotionStage) == 4


def test_stage_max_mode_complete_mapping() -> None:
    """Every stage maps to a defined mode; the mapping is exactly the one in
    the safety-verification record."""
    assert stage_max_mode(PromotionStage.STAGE_1) is RemediationMode.RECOMMEND
    assert stage_max_mode(PromotionStage.STAGE_2) is RemediationMode.DRY_RUN
    assert stage_max_mode(PromotionStage.STAGE_3) is RemediationMode.EXECUTE
    assert stage_max_mode(PromotionStage.STAGE_4) is RemediationMode.EXECUTE


# ---------------------------- PromotionEvidence --------------------------


def test_evidence_defaults_to_zero_counters() -> None:
    """A fresh evidence record has all counters at zero — newly-tracked
    action classes have accumulated nothing."""
    e = PromotionEvidence()
    assert e.stage1_artifacts == 0
    assert e.stage2_dry_runs == 0
    assert e.stage3_executes == 0
    assert e.stage3_consecutive_executes == 0
    assert e.stage3_unexpected_rollbacks == 0
    assert e.stage3_distinct_workloads == []


def test_evidence_rejects_negative_counters() -> None:
    """Pydantic Field(ge=0) blocks negative integers — guards against
    operator typos or replay bugs."""
    with pytest.raises(ValidationError):
        PromotionEvidence(stage2_dry_runs=-1)


def test_evidence_rejects_extra_fields() -> None:
    """extra='forbid' catches operator typos like `stage_three_executes`
    that would otherwise silently be lost."""
    with pytest.raises(ValidationError):
        PromotionEvidence(stage_three_executes=5)  # type: ignore[call-arg]


def test_evidence_unexpected_rollbacks_independent_of_executes() -> None:
    """`stage3_unexpected_rollbacks` and `stage3_executes` are independent
    counters. The realistic case "first Stage-3 attempt rolls back" produces
    `unexpected_rollbacks=1, stage3_executes=0` — this must be a valid state.

    An earlier schema rejected this with an `unexpected_rollbacks <= stage3_executes`
    invariant; that was wrong (the chain reconciler in Task 6 hits this state
    naturally). The invariant has been removed.
    """
    # Realistic case: rollback before any validated execute.
    e = PromotionEvidence(stage3_executes=0, stage3_unexpected_rollbacks=1)
    assert e.stage3_unexpected_rollbacks == 1
    assert e.stage3_executes == 0
    # Also valid: many rollbacks with zero validateds.
    e2 = PromotionEvidence(stage3_executes=2, stage3_unexpected_rollbacks=10)
    assert e2.stage3_unexpected_rollbacks == 10


def test_evidence_consecutive_bounded_by_total() -> None:
    """Consecutive run-length cannot exceed the total execution count."""
    with pytest.raises(ValidationError, match="stage3_consecutive_executes"):
        PromotionEvidence(stage3_executes=5, stage3_consecutive_executes=10)


def test_evidence_workloads_deduped_and_sorted() -> None:
    """Duplicates are stripped; the resulting list is sorted so equal
    populations produce identical persisted state regardless of ingest order."""
    e = PromotionEvidence(stage3_distinct_workloads=["b/x", "a/y", "b/x", "a/y", "c/z"])
    assert e.stage3_distinct_workloads == ["a/y", "b/x", "c/z"]


def test_evidence_validate_assignment_re_checks() -> None:
    """validate_assignment=True means counter increments are re-validated."""
    e = PromotionEvidence(stage3_executes=2)
    e.stage3_executes = 5  # ok
    assert e.stage3_executes == 5
    with pytest.raises(ValidationError):
        e.stage3_executes = -1


# ---------------------------- PromotionSignOff ---------------------------


_NOW = datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


def test_signoff_advance_must_be_plus_one() -> None:
    """Advance transitions move exactly +1 stage — Stage-2 → Stage-4 is
    forbidden by the safety contract (no skipping Stage 3)."""
    # Valid +1.
    PromotionSignOff(
        event_kind="advance",
        operator="alice",
        timestamp=_NOW,
        reason="dry-runs passed",
        from_stage=PromotionStage.STAGE_2,
        to_stage=PromotionStage.STAGE_3,
    )
    # Invalid +2.
    with pytest.raises(ValidationError, match="advance must move exactly"):
        PromotionSignOff(
            event_kind="advance",
            operator="alice",
            timestamp=_NOW,
            reason="trying to skip",
            from_stage=PromotionStage.STAGE_2,
            to_stage=PromotionStage.STAGE_4,
        )


def test_signoff_demote_must_decrease() -> None:
    """Demote can move to any strictly-lower stage."""
    # Valid -2.
    PromotionSignOff(
        event_kind="demote",
        operator="alice",
        timestamp=_NOW,
        reason="incident #42",
        from_stage=PromotionStage.STAGE_3,
        to_stage=PromotionStage.STAGE_1,
    )
    # Invalid: same stage.
    with pytest.raises(ValidationError, match="no-op"):
        PromotionSignOff(
            event_kind="demote",
            operator="alice",
            timestamp=_NOW,
            reason="nothing",
            from_stage=PromotionStage.STAGE_3,
            to_stage=PromotionStage.STAGE_3,
        )


def test_signoff_demote_cannot_advance() -> None:
    """A demote that moves to a higher stage is rejected — would be a typo."""
    with pytest.raises(ValidationError, match="strictly lower"):
        PromotionSignOff(
            event_kind="demote",
            operator="alice",
            timestamp=_NOW,
            reason="oops",
            from_stage=PromotionStage.STAGE_2,
            to_stage=PromotionStage.STAGE_3,
        )


def test_signoff_requires_reason() -> None:
    """Empty reason is rejected — the audit trail must always carry justification."""
    with pytest.raises(ValidationError):
        PromotionSignOff(
            event_kind="advance",
            operator="alice",
            timestamp=_NOW,
            reason="",
            from_stage=PromotionStage.STAGE_1,
            to_stage=PromotionStage.STAGE_2,
        )


def test_signoff_requires_operator() -> None:
    """Empty operator is rejected — every transition is owned by a named human."""
    with pytest.raises(ValidationError):
        PromotionSignOff(
            event_kind="advance",
            operator="",
            timestamp=_NOW,
            reason="evidence",
            from_stage=PromotionStage.STAGE_1,
            to_stage=PromotionStage.STAGE_2,
        )


def test_signoff_rejects_naive_timestamp() -> None:
    """Naive datetime is rejected — UTC awareness is required for cross-tz audit replay."""
    naive = datetime(2026, 5, 17, 12, 0, 0)
    with pytest.raises(ValidationError, match="timezone-aware"):
        PromotionSignOff(
            event_kind="advance",
            operator="alice",
            timestamp=naive,
            reason="x",
            from_stage=PromotionStage.STAGE_1,
            to_stage=PromotionStage.STAGE_2,
        )


def test_signoff_normalises_non_utc_to_utc() -> None:
    """A timezone-aware non-UTC timestamp is accepted and converted to UTC."""
    pst = timezone(timedelta(hours=-8))
    pst_time = datetime(2026, 5, 17, 4, 0, 0, tzinfo=pst)
    s = PromotionSignOff(
        event_kind="advance",
        operator="alice",
        timestamp=pst_time,
        reason="x",
        from_stage=PromotionStage.STAGE_1,
        to_stage=PromotionStage.STAGE_2,
    )
    assert s.timestamp.tzinfo is UTC
    assert s.timestamp.hour == 12  # 4am PST == 12pm UTC


# ---------------------------- ActionClassPromotion -----------------------


def _signoff(
    *,
    operator: str = "alice",
    when: datetime | None = None,
    reason: str = "ok",
    from_stage: PromotionStage,
    to_stage: PromotionStage,
    kind: str = "advance",
) -> PromotionSignOff:
    return PromotionSignOff(
        event_kind=kind,  # type: ignore[arg-type]
        operator=operator,
        timestamp=when or _NOW,
        reason=reason,
        from_stage=from_stage,
        to_stage=to_stage,
    )


def test_action_class_default_stage_is_1_with_no_signoffs() -> None:
    """A freshly-tracked action class with no history defaults to Stage 1."""
    p = ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
    )
    assert p.stage == PromotionStage.STAGE_1
    assert p.sign_offs == []


def test_action_class_rejects_higher_stage_without_signoff() -> None:
    """An action class can only be at Stage 2+ if there's a sign-off for it
    — this prevents promotion.yaml from claiming a stage without audit history."""
    with pytest.raises(ValidationError, match="only Stage 1 is permitted"):
        ActionClassPromotion(
            action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            stage=PromotionStage.STAGE_3,
        )


def test_action_class_stage_must_match_latest_signoff() -> None:
    """`stage` must equal the `to_stage` of the most recent sign-off."""
    s = _signoff(from_stage=PromotionStage.STAGE_1, to_stage=PromotionStage.STAGE_2)
    # Valid.
    ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        stage=PromotionStage.STAGE_2,
        sign_offs=[s],
    )
    # Invalid (stage says 3 but the only sign-off says 2).
    with pytest.raises(ValidationError, match="does not match the most recent sign-off"):
        ActionClassPromotion(
            action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            stage=PromotionStage.STAGE_3,
            sign_offs=[s],
        )


def test_action_class_signoffs_must_be_chronologically_ordered() -> None:
    """sign_offs[-1].timestamp must be ≥ sign_offs[-2].timestamp — guards
    replay-driven reconstruction against out-of-order events."""
    s1 = _signoff(
        when=_NOW + timedelta(days=2),
        from_stage=PromotionStage.STAGE_1,
        to_stage=PromotionStage.STAGE_2,
    )
    s2 = _signoff(
        when=_NOW,  # earlier than s1 — wrong order
        from_stage=PromotionStage.STAGE_2,
        to_stage=PromotionStage.STAGE_3,
    )
    with pytest.raises(ValidationError, match="chronologically ordered"):
        ActionClassPromotion(
            action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            stage=PromotionStage.STAGE_3,
            sign_offs=[s1, s2],
        )


def test_action_class_multi_signoff_path_to_stage_3() -> None:
    """A Stage-1 → Stage-2 → Stage-3 path with two consecutive sign-offs."""
    s12 = _signoff(
        when=_NOW,
        from_stage=PromotionStage.STAGE_1,
        to_stage=PromotionStage.STAGE_2,
    )
    s23 = _signoff(
        when=_NOW + timedelta(days=14),
        from_stage=PromotionStage.STAGE_2,
        to_stage=PromotionStage.STAGE_3,
    )
    p = ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        stage=PromotionStage.STAGE_3,
        sign_offs=[s12, s23],
    )
    assert p.stage == PromotionStage.STAGE_3
    assert len(p.sign_offs) == 2


# ---------------------------- PromotionFile ------------------------------


def _now_pair() -> tuple[datetime, datetime]:
    return _NOW, _NOW


def test_promotion_file_schema_version_constant() -> None:
    """The constant is the literal `"0.1"` and PromotionFile defaults to it."""
    assert PROMOTION_FILE_SCHEMA_VERSION == "0.1"
    created, modified = _now_pair()
    f = PromotionFile(cluster_id="prod-eu-1", created_at=created, last_modified_at=modified)
    assert f.schema_version == "0.1"


def test_promotion_file_rejects_unknown_schema_version() -> None:
    """A v0.2 file should not load as v0.1 — bumping the schema requires
    explicit migration."""
    created, modified = _now_pair()
    with pytest.raises(ValidationError):
        PromotionFile(
            schema_version="0.2",  # type: ignore[arg-type]
            cluster_id="prod-eu-1",
            created_at=created,
            last_modified_at=modified,
        )


def test_promotion_file_rejects_naive_timestamps() -> None:
    """Same UTC discipline as PromotionSignOff."""
    naive = datetime(2026, 5, 17, 12, 0, 0)
    with pytest.raises(ValidationError):
        PromotionFile(cluster_id="prod-eu-1", created_at=naive, last_modified_at=_NOW)


def test_promotion_file_last_modified_after_created() -> None:
    """`last_modified_at >= created_at` — clock skew or tampering otherwise."""
    with pytest.raises(ValidationError, match=r"last_modified_at.*<.*created_at"):
        PromotionFile(
            cluster_id="prod-eu-1",
            created_at=_NOW,
            last_modified_at=_NOW - timedelta(seconds=1),
        )


def test_promotion_file_empty_action_classes_is_valid() -> None:
    """`remediation promotion init` writes a file with no action classes —
    every action class then defaults to Stage 1 at lookup time."""
    created, modified = _now_pair()
    f = PromotionFile(cluster_id="prod-eu-1", created_at=created, last_modified_at=modified)
    assert f.action_classes == {}


def test_promotion_file_action_class_key_must_match_action_type() -> None:
    """Map key must equal the embedded action_type — typo guard."""
    created, modified = _now_pair()
    promotion = ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
    )
    # Wrong key.
    with pytest.raises(ValidationError, match="key and action_type must match"):
        PromotionFile(
            cluster_id="prod-eu-1",
            created_at=created,
            last_modified_at=modified,
            action_classes={"remediation_k8s_patch_imagePullPolicy_Always": promotion},
        )


def test_promotion_file_action_class_key_must_be_registered() -> None:
    """An unknown key is rejected — would silently default the action to
    Stage 1, which is the wrong failure mode (operator should see the error)."""
    created, modified = _now_pair()
    promotion = ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
    )
    with pytest.raises(ValidationError, match="not a registered RemediationActionType"):
        PromotionFile(
            cluster_id="prod-eu-1",
            created_at=created,
            last_modified_at=modified,
            action_classes={"made_up_action_class": promotion},
        )


def test_promotion_file_round_trip_via_model_dump_and_validate() -> None:
    """A full file with one action class round-trips through model_dump +
    model_validate without loss — the YAML save/load contract Tracker.save()
    will rely on in Task 3."""
    created, modified = _now_pair()
    signoff = _signoff(
        from_stage=PromotionStage.STAGE_1,
        to_stage=PromotionStage.STAGE_2,
    )
    promotion = ActionClassPromotion(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        stage=PromotionStage.STAGE_2,
        evidence=PromotionEvidence(
            stage1_artifacts=3,
            stage2_dry_runs=7,
            stage3_distinct_workloads=["prod/api", "prod/web"],
        ),
        sign_offs=[signoff],
    )
    f = PromotionFile(
        cluster_id="prod-eu-1",
        created_at=created,
        last_modified_at=modified,
        action_classes={
            "remediation_k8s_patch_runAsNonRoot": promotion,
        },
    )

    # Round-trip via the dict shape Tracker.save() will write to YAML.
    payload = f.model_dump(mode="json")
    restored = PromotionFile.model_validate(payload)
    assert restored.cluster_id == "prod-eu-1"
    assert (
        restored.action_classes["remediation_k8s_patch_runAsNonRoot"].stage
        == PromotionStage.STAGE_2
    )
    assert restored.action_classes[
        "remediation_k8s_patch_runAsNonRoot"
    ].evidence.stage3_distinct_workloads == ["prod/api", "prod/web"]
    assert len(restored.action_classes["remediation_k8s_patch_runAsNonRoot"].sign_offs) == 1


def test_promotion_file_rejects_extra_fields() -> None:
    """extra='forbid' catches operator typos at the file-root level too."""
    created, modified = _now_pair()
    with pytest.raises(ValidationError):
        PromotionFile.model_validate(
            {
                "schema_version": "0.1",
                "cluster_id": "prod-eu-1",
                "created_at": created.isoformat(),
                "last_modified_at": modified.isoformat(),
                "action_classes": {},
                "rouge_field": "should be rejected",
            }
        )
