"""Task 4 audit-shim tests for the 9 `promotion.*` events.

Covers the 5 `PipelineAuditor.record_promotion_*` methods that bridge the
in-memory promotion tracker (Task 3) to the F.6 hash-chained audit log
(safety-verification §3's source-of-truth contract).

What this proves:

1. Each method emits the expected `action` string + payload shape.
2. `record_promotion_evidence` validates the event name and rejects:
   - unknown strings;
   - transition events (advance/demote/init/proposed/reconcile);
   - missing `workload` for Stage-3 evidence.
3. `record_promotion_transition` dispatches advance / demote correctly.
4. Every emitted entry extends the F.6 chain (hash links).
5. `all_action_names()` returns all 20 actions (11 remediation + 9 promotion).
6. Promotion events interleave cleanly with the existing remediation
   vocabulary in a mixed-emit chain.

Task 5 wires evidence emission into the agent driver; Tasks 6-8 wire the
proposal / transition / init / reconcile emitters into the reconciler +
CLI. These tests prove the audit surface independent of those callers.
"""

from __future__ import annotations

import itertools
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from remediation.audit import (
    ACTION_PROMOTION_ADVANCE_APPLIED,
    ACTION_PROMOTION_ADVANCE_PROPOSED,
    ACTION_PROMOTION_DEMOTE_APPLIED,
    ACTION_PROMOTION_EVIDENCE_STAGE1,
    ACTION_PROMOTION_EVIDENCE_STAGE2,
    ACTION_PROMOTION_EVIDENCE_STAGE3,
    ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
    ACTION_PROMOTION_INIT_APPLIED,
    ACTION_PROMOTION_RECONCILE_COMPLETED,
    ACTION_RUN_STARTED,
    PROMOTION_ACTIONS,
    PipelineAuditor,
    all_action_names,
)
from remediation.promotion.schemas import PromotionSignOff, PromotionStage
from remediation.promotion.tracker import PromotionProposal
from remediation.schemas import RemediationActionType, RemediationMode

_NOW = datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


# ---------------------------- helpers -----------------------------------


def _auditor(tmp_path: Path) -> PipelineAuditor:
    return PipelineAuditor(tmp_path / "audit.jsonl", run_id="run-promo-test")


def _read_entries(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# ---------------------------- record_promotion_evidence -----------------


def test_record_promotion_evidence_stage1(tmp_path: Path) -> None:
    auditor = _auditor(tmp_path)
    entry = auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
        correlation_id="corr-001",
    )
    assert entry.action == ACTION_PROMOTION_EVIDENCE_STAGE1
    assert entry.payload["action_type"] == "remediation_k8s_patch_runAsNonRoot"
    assert entry.payload["correlation_id"] == "corr-001"
    assert entry.payload["event"] == ACTION_PROMOTION_EVIDENCE_STAGE1
    # Stage-1 events have no workload semantically.
    assert "workload" not in entry.payload


def test_record_promotion_evidence_stage2(tmp_path: Path) -> None:
    auditor = _auditor(tmp_path)
    entry = auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE2,
    )
    assert entry.action == ACTION_PROMOTION_EVIDENCE_STAGE2
    assert entry.payload["action_type"] == "remediation_k8s_patch_runAsNonRoot"


def test_record_promotion_evidence_stage3_with_workload(tmp_path: Path) -> None:
    """Stage-3 events MUST carry the workload identifier — the reconciler
    relies on it to rebuild `stage3_distinct_workloads`."""
    auditor = _auditor(tmp_path)
    entry = auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE3,
        workload="production/api",
        correlation_id="corr-002",
    )
    assert entry.action == ACTION_PROMOTION_EVIDENCE_STAGE3
    assert entry.payload["workload"] == "production/api"
    assert entry.payload["correlation_id"] == "corr-002"


def test_record_promotion_evidence_unexpected_rollback(tmp_path: Path) -> None:
    """Unexpected rollback events don't require a workload (the rollback
    fact is what counts; the reconciler resets `consecutive_executes` on
    seeing the action_type)."""
    auditor = _auditor(tmp_path)
    entry = auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
        correlation_id="corr-003",
    )
    assert entry.action == ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK


def test_record_promotion_evidence_rejects_unknown_event(tmp_path: Path) -> None:
    auditor = _auditor(tmp_path)
    with pytest.raises(ValueError, match="unknown evidence event"):
        auditor.record_promotion_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event="not.real",
        )


def test_record_promotion_evidence_rejects_transition_events(tmp_path: Path) -> None:
    """Transition events belong to record_promotion_proposal /
    record_promotion_transition / record_promotion_init /
    record_promotion_reconcile — never to record_promotion_evidence."""
    auditor = _auditor(tmp_path)
    for transition_event in (
        ACTION_PROMOTION_ADVANCE_PROPOSED,
        ACTION_PROMOTION_ADVANCE_APPLIED,
        ACTION_PROMOTION_DEMOTE_APPLIED,
        ACTION_PROMOTION_INIT_APPLIED,
        ACTION_PROMOTION_RECONCILE_COMPLETED,
    ):
        with pytest.raises(ValueError, match="unknown evidence event"):
            auditor.record_promotion_evidence(
                RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
                event=transition_event,
            )


def test_record_promotion_evidence_stage3_requires_workload(tmp_path: Path) -> None:
    auditor = _auditor(tmp_path)
    with pytest.raises(ValueError, match="workload is required"):
        auditor.record_promotion_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=None,
        )
    with pytest.raises(ValueError, match="workload is required"):
        auditor.record_promotion_evidence(
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload="   ",
        )


# ---------------------------- record_promotion_proposal -----------------


def test_record_promotion_proposal(tmp_path: Path) -> None:
    auditor = _auditor(tmp_path)
    proposal = PromotionProposal(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        from_stage=PromotionStage.STAGE_2,
        to_stage=PromotionStage.STAGE_3,
        reason="5 successful dry-runs accumulated.",
        evidence_summary={"stage2_dry_runs": 5},
    )
    entry = auditor.record_promotion_proposal(proposal)
    assert entry.action == ACTION_PROMOTION_ADVANCE_PROPOSED
    assert entry.payload["action_type"] == "remediation_k8s_patch_runAsNonRoot"
    assert entry.payload["from_stage"] == 2
    assert entry.payload["to_stage"] == 3
    assert entry.payload["reason"] == "5 successful dry-runs accumulated."
    assert entry.payload["evidence_summary"] == {"stage2_dry_runs": 5}


# ---------------------------- record_promotion_transition ---------------


def test_record_promotion_transition_advance(tmp_path: Path) -> None:
    """An advance sign-off emits `promotion.advance.applied`."""
    auditor = _auditor(tmp_path)
    signoff = PromotionSignOff(
        event_kind="advance",
        operator="alice",
        timestamp=_NOW,
        reason="dry-runs passed; promoting",
        from_stage=PromotionStage.STAGE_2,
        to_stage=PromotionStage.STAGE_3,
    )
    entry = auditor.record_promotion_transition(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        signoff,
    )
    assert entry.action == ACTION_PROMOTION_ADVANCE_APPLIED
    assert entry.payload["event_kind"] == "advance"
    assert entry.payload["operator"] == "alice"
    assert entry.payload["from_stage"] == 2
    assert entry.payload["to_stage"] == 3
    assert entry.payload["reason"] == "dry-runs passed; promoting"
    assert entry.payload["timestamp"] == _NOW.isoformat()


def test_record_promotion_transition_demote(tmp_path: Path) -> None:
    """A demote sign-off emits `promotion.demote.applied`."""
    auditor = _auditor(tmp_path)
    signoff = PromotionSignOff(
        event_kind="demote",
        operator="bob",
        timestamp=_NOW,
        reason="incident #42 — webhook started mutating",
        from_stage=PromotionStage.STAGE_3,
        to_stage=PromotionStage.STAGE_1,
    )
    entry = auditor.record_promotion_transition(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        signoff,
    )
    assert entry.action == ACTION_PROMOTION_DEMOTE_APPLIED
    assert entry.payload["event_kind"] == "demote"
    assert entry.payload["from_stage"] == 3
    assert entry.payload["to_stage"] == 1


# ---------------------------- record_promotion_init ---------------------


def test_record_promotion_init(tmp_path: Path) -> None:
    auditor = _auditor(tmp_path)
    entry = auditor.record_promotion_init(
        cluster_id="prod-eu-1",
        action_classes=[
            "remediation_k8s_patch_runAsNonRoot",
            "remediation_k8s_patch_resource_limits",
        ],
    )
    assert entry.action == ACTION_PROMOTION_INIT_APPLIED
    assert entry.payload["cluster_id"] == "prod-eu-1"
    assert entry.payload["action_classes"] == [
        "remediation_k8s_patch_runAsNonRoot",
        "remediation_k8s_patch_resource_limits",
    ]
    assert entry.payload["default_stage"] == 1


# ---------------------------- record_promotion_reconcile ----------------


def test_record_promotion_reconcile(tmp_path: Path) -> None:
    auditor = _auditor(tmp_path)
    entry = auditor.record_promotion_reconcile(
        chain_entries_replayed=42,
        state_changes={
            "remediation_k8s_patch_runAsNonRoot": {"stage": "2 → 3"},
        },
    )
    assert entry.action == ACTION_PROMOTION_RECONCILE_COMPLETED
    assert entry.payload["chain_entries_replayed"] == 42
    assert entry.payload["state_changes"] == {
        "remediation_k8s_patch_runAsNonRoot": {"stage": "2 → 3"},
    }


def test_record_promotion_reconcile_empty_state_changes(tmp_path: Path) -> None:
    """Reconcile run with zero diffs — file already matched the chain."""
    auditor = _auditor(tmp_path)
    entry = auditor.record_promotion_reconcile(
        chain_entries_replayed=7,
        state_changes={},
    )
    assert entry.payload["state_changes"] == {}


# ---------------------------- chain integrity ---------------------------


def test_promotion_events_extend_chain_with_hash_links(tmp_path: Path) -> None:
    """Each promotion event appends to the chain and links to the previous
    entry's hash. The chain integrity is what makes the audit log the
    source of truth for promotion state."""
    auditor = _auditor(tmp_path)
    auditor.run_started(
        mode=RemediationMode.RECOMMEND,
        findings_path="/dev/null",
        authorized_actions=[],
        max_actions_per_run=5,
        rollback_window_sec=300,
    )
    auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )
    auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE2,
    )

    entries = _read_entries(auditor.path)
    assert len(entries) >= 3
    # Each entry's `previous_hash` matches the prior entry's `entry_hash`.
    for prev, curr in itertools.pairwise(entries):
        assert curr["previous_hash"] == prev["entry_hash"], (
            f"chain link broken: {curr['action']}.previous_hash != prior.entry_hash"
        )


def test_promotion_and_remediation_events_interleave(tmp_path: Path) -> None:
    """A mixed chain (remediation + promotion) is well-formed — promotion
    events don't displace or corrupt the existing remediation vocabulary."""
    auditor = _auditor(tmp_path)
    auditor.run_started(
        mode=RemediationMode.RECOMMEND,
        findings_path="/dev/null",
        authorized_actions=["remediation_k8s_patch_runAsNonRoot"],
        max_actions_per_run=5,
        rollback_window_sec=300,
    )
    auditor.findings_ingested(count=1, source_path="ignored/findings.json")
    auditor.record_promotion_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )
    auditor.run_completed(outcome_counts={"recommended_only": 1}, total_actions=1)

    actions = [e["action"] for e in _read_entries(auditor.path)]
    assert actions[0] == ACTION_RUN_STARTED
    assert ACTION_PROMOTION_EVIDENCE_STAGE1 in actions
    assert actions[-1] == "remediation.run_completed"


# ---------------------------- vocabulary surface ------------------------


def test_all_action_names_includes_all_20() -> None:
    """The total vocabulary is exactly 20 actions: 11 remediation + 9 promotion."""
    names = all_action_names()
    assert len(names) == 20
    # 9 promotion actions are present.
    promotion_in_vocab = {n for n in names if n.startswith("promotion.")}
    assert promotion_in_vocab == set(PROMOTION_ACTIONS)
    # 11 remediation actions are present.
    remediation_in_vocab = {n for n in names if n.startswith("remediation.")}
    assert len(remediation_in_vocab) == 11


def test_all_action_names_is_stable_order() -> None:
    """Calling twice returns the same tuple — downstream tooling can rely
    on the order for documentation generation."""
    assert all_action_names() == all_action_names()
