"""Task 8 reconcile-CLI tests.

Covers the `remediation promotion reconcile` subcommand — the operator-
facing bridge from Task 6's `replay()` function to disk.

Two safety properties dominate this file:

1. **Stage-4 refusal.** If the audit chain materialises any action class
   at Stage 4, `reconcile` refuses with the two Phase-1c prerequisites
   from safety-verification §6. The refusal is itself audited
   (`promotion.reconcile.completed` with `refused=true`), and
   `promotion.yaml` is NOT modified. This holds even if the chain was
   well-formed at the time of emission — v0.1.1 won't materialise
   Stage 4 regardless of what the chain says.

2. **--dry-run is read-only.** A dry-run prints the diff to stdout but
   touches neither `promotion.yaml` nor the audit chain. The operator
   can audit the plan before committing.

Other surface coverage: round-trip parity with the CLI advance/demote
flow (Task 7), no-change preview, chain corruption handling, and the
"chain materialises stuff the existing file is missing" diff path.
"""

from __future__ import annotations

import json
from pathlib import Path

from charter.audit import AuditLog
from click.testing import CliRunner
from remediation.audit import PipelineAuditor
from remediation.cli import main
from remediation.promotion import (
    PromotionSignOff,
    PromotionStage,
    PromotionTracker,
)
from remediation.promotion.events import (
    ACTION_PROMOTION_RECONCILE_COMPLETED,
)
from remediation.schemas import RemediationActionType

_RUN_AS_ROOT = "remediation_k8s_patch_runAsNonRoot"
_RESOURCE_LIMITS = "remediation_k8s_patch_resource_limits"


# ---------------------------- helpers -----------------------------------


def _audit_actions(audit_path: Path) -> list[str]:
    if not audit_path.exists():
        return []
    return [
        json.loads(line)["action"]
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _audit_payloads(audit_path: Path, action: str) -> list[dict]:
    if not audit_path.exists():
        return []
    return [
        json.loads(line)["payload"]
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line and json.loads(line)["action"] == action
    ]


def _init_and_advance_to_stage_3(promotion: Path, audit: Path) -> CliRunner:
    """Convenience: init promotion.yaml + advance runAsNonRoot to Stage 3 via the CLI."""
    runner = CliRunner()
    runner.invoke(
        main,
        [
            "promotion",
            "init",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
            "--cluster-id",
            "prod-eu-1",
        ],
    )
    for next_stage in ("stage_2", "stage_3"):
        runner.invoke(
            main,
            [
                "promotion",
                "advance",
                "--promotion",
                str(promotion),
                "--audit",
                str(audit),
                "--action",
                _RUN_AS_ROOT,
                "--to",
                next_stage,
                "--reason",
                "test fixture",
            ],
        )
    return runner


def _inject_stage_4_chain_entry(audit_path: Path) -> None:
    """Bypass Task 7's CLI gate to inject a Stage 3 → Stage 4 sign-off into
    the chain. This is the synthetic "chain from a future A.1 version that
    allowed Stage 4" scenario the reconcile gate exists to handle.

    We construct the PromotionSignOff via Pydantic directly (which accepts
    +1 advances including 3 → 4 — the gate that refuses Stage 4 lives in
    the CLI, not the schema), then write it to the audit log through
    PipelineAuditor.
    """
    from datetime import UTC, datetime

    signoff = PromotionSignOff(
        event_kind="advance",
        operator="future-agent",
        timestamp=datetime.now(UTC),
        reason="prerequisite work completed (synthetic test fixture)",
        from_stage=PromotionStage.STAGE_3,
        to_stage=PromotionStage.STAGE_4,
    )
    auditor = PipelineAuditor(audit_path, run_id="future-version-injection")
    auditor.record_promotion_transition(RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT, signoff)


# ---------------------------- empty / init-only ------------------------


def test_reconcile_empty_chain_produces_empty_file(tmp_path: Path) -> None:
    """An audit log with no promotion.* entries → an empty PromotionFile
    is written (cluster_id from the --cluster-id flag, no action classes)."""
    audit = tmp_path / "audit.jsonl"
    audit.write_text("")  # empty file (click's exists=True needs a file present)
    promotion = tmp_path / "promotion.yaml"

    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
            "--cluster-id",
            "fresh-env",
        ],
    )
    assert result.exit_code == 0, result.output
    assert promotion.exists()
    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    assert tracker.file.cluster_id == "fresh-env"
    assert tracker.file.action_classes == {}


def test_reconcile_init_only_chain(tmp_path: Path) -> None:
    """Chain with just init.applied → file with action classes at Stage 1."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    auditor = PipelineAuditor(audit, run_id="init-only")
    auditor.record_promotion_init(
        cluster_id="prod-eu-1", action_classes=[_RUN_AS_ROOT, _RESOURCE_LIMITS]
    )

    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
        ],
    )
    assert result.exit_code == 0, result.output
    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    assert tracker.file.cluster_id == "prod-eu-1"
    assert set(tracker.file.action_classes) == {_RUN_AS_ROOT, _RESOURCE_LIMITS}
    for entry in tracker.file.action_classes.values():
        assert entry.stage is PromotionStage.STAGE_1


# ---------------------------- round-trip with CLI history --------------


def test_reconcile_replays_advance_history(tmp_path: Path) -> None:
    """Replay the chain that init + advance built; the rebuilt file should
    match the live tracker's state for runAsNonRoot at Stage 3."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    _init_and_advance_to_stage_3(promotion, audit)

    # The live tracker after CLI advances:
    live_tracker = PromotionTracker.from_path(promotion)
    assert live_tracker is not None
    live_state = live_tracker.file.action_classes[_RUN_AS_ROOT].stage
    assert live_state is PromotionStage.STAGE_3

    # Reconcile to a different output path to compare.
    rebuilt_promotion = tmp_path / "rebuilt.yaml"
    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(rebuilt_promotion),
            "--audit",
            str(audit),
        ],
    )
    assert result.exit_code == 0, result.output
    rebuilt = PromotionTracker.from_path(rebuilt_promotion)
    assert rebuilt is not None
    assert rebuilt.file.action_classes[_RUN_AS_ROOT].stage is PromotionStage.STAGE_3
    assert len(rebuilt.file.action_classes[_RUN_AS_ROOT].sign_offs) == 2


# ---------------------------- audit emission ---------------------------


def test_reconcile_emits_completed_audit_entry(tmp_path: Path) -> None:
    """A successful reconcile appends a promotion.reconcile.completed
    entry with refused=False."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    _init_and_advance_to_stage_3(promotion, audit)

    CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(tmp_path / "rebuilt.yaml"),
            "--audit",
            str(audit),
        ],
    )

    payloads = _audit_payloads(audit, ACTION_PROMOTION_RECONCILE_COMPLETED)
    assert len(payloads) == 1
    assert payloads[0]["refused"] is False
    assert payloads[0]["chain_entries_replayed"] >= 3  # init + 2 advances


# ---------------------------- dry-run ----------------------------------


def test_reconcile_dry_run_does_not_write_promotion_yaml(tmp_path: Path) -> None:
    """--dry-run mode prints the diff but doesn't write the file."""
    audit = tmp_path / "audit.jsonl"
    auditor = PipelineAuditor(audit, run_id="dry-run-test")
    auditor.record_promotion_init(cluster_id="prod-eu-1", action_classes=[_RUN_AS_ROOT])

    # Target path doesn't exist before reconcile.
    rebuilt = tmp_path / "rebuilt.yaml"
    assert not rebuilt.exists()

    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(rebuilt),
            "--audit",
            str(audit),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert not rebuilt.exists(), "dry-run must NOT create the target file"
    assert "dry-run" in result.output.lower()


def test_reconcile_dry_run_does_not_emit_audit_entry(tmp_path: Path) -> None:
    """--dry-run produces no promotion.reconcile.completed entry."""
    audit = tmp_path / "audit.jsonl"
    auditor = PipelineAuditor(audit, run_id="dry-run-audit-test")
    auditor.record_promotion_init(cluster_id="prod-eu-1", action_classes=[_RUN_AS_ROOT])

    CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(tmp_path / "rebuilt.yaml"),
            "--audit",
            str(audit),
            "--dry-run",
        ],
    )

    payloads = _audit_payloads(audit, ACTION_PROMOTION_RECONCILE_COMPLETED)
    assert payloads == [], "dry-run must not emit a reconcile.completed audit entry"


def test_reconcile_dry_run_shows_state_changes(tmp_path: Path) -> None:
    """--dry-run output names the action classes that would change."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    _init_and_advance_to_stage_3(promotion, audit)

    # Reconcile to a NEW path so the diff shows "appeared" entries.
    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(tmp_path / "fresh.yaml"),
            "--audit",
            str(audit),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert _RUN_AS_ROOT in result.output
    assert "STAGE_3" in result.output  # the chain materialises Stage 3


def test_reconcile_no_changes_message(tmp_path: Path) -> None:
    """When the existing promotion.yaml already matches the chain, the
    reconcile reports zero state changes and still emits the audit entry."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    _init_and_advance_to_stage_3(promotion, audit)

    # Run reconcile in-place — promotion.yaml already matches what the chain says.
    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "no state changes" in result.output.lower()


# ---------------------------- Stage-4 gate (load-bearing) --------------


def test_reconcile_refuses_stage_4_state(tmp_path: Path) -> None:
    """**Load-bearing test for Task 8.** A chain that materialises any
    action class at Stage 4 → reconcile refuses, citing the two
    Phase-1c prerequisites. promotion.yaml is NOT modified. The
    refusal is recorded in the audit chain so forensics can find it.
    """
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"

    # Build chain up to Stage 3 via the CLI (allowed), then INJECT a Stage 3
    # → Stage 4 advance bypassing the Task-7 CLI gate.
    _init_and_advance_to_stage_3(promotion, audit)
    _inject_stage_4_chain_entry(audit)

    # Capture promotion.yaml content before reconcile.
    before_content = promotion.read_text()

    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
        ],
    )

    # Refusal: non-zero exit + Stage 4 message in stderr.
    assert result.exit_code != 0
    assert "Stage 4" in result.output
    assert "rolled-back-path webhook" in result.output
    assert "Stage-3 evidence" in result.output
    assert _RUN_AS_ROOT in result.output

    # promotion.yaml content unchanged.
    after_content = promotion.read_text()
    assert before_content == after_content, "refused reconcile must NOT modify promotion.yaml"
    # State on disk still says Stage 3 (chain's Stage 4 entry was not materialised).
    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    assert tracker.file.action_classes[_RUN_AS_ROOT].stage is PromotionStage.STAGE_3


def test_reconcile_refusal_is_audited(tmp_path: Path) -> None:
    """The refused reconcile attempt emits a promotion.reconcile.completed
    entry with refused=True + a refusal_reason in the payload."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    _init_and_advance_to_stage_3(promotion, audit)
    _inject_stage_4_chain_entry(audit)

    # Count audit entries before.
    before_count = len(_audit_actions(audit))

    CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
        ],
    )

    # One new audit entry: the reconcile.completed (refused=True).
    after_actions = _audit_actions(audit)
    assert len(after_actions) == before_count + 1
    assert after_actions[-1] == ACTION_PROMOTION_RECONCILE_COMPLETED

    # Payload carries refused=True + refusal_reason.
    payloads = _audit_payloads(audit, ACTION_PROMOTION_RECONCILE_COMPLETED)
    assert len(payloads) == 1
    assert payloads[0]["refused"] is True
    assert "Stage 4" in payloads[0]["refusal_reason"]
    assert _RUN_AS_ROOT in payloads[0]["refusal_reason"]


# ---------------------------- chain corruption / edge cases ------------


def test_reconcile_filters_non_promotion_entries(tmp_path: Path) -> None:
    """The audit chain may contain remediation.* events (from
    `remediation run` invocations) interleaved with promotion.* events.
    The reconcile silently filters non-promotion entries."""
    audit = tmp_path / "audit.jsonl"
    promotion = tmp_path / "promotion.yaml"
    # Mix a few events: init, then a remediation.run_started, then advance.
    auditor = PipelineAuditor(audit, run_id="mixed-chain")
    auditor.record_promotion_init(cluster_id="dev", action_classes=[_RUN_AS_ROOT])
    from remediation.audit import ACTION_RUN_STARTED

    auditor._log.append(
        ACTION_RUN_STARTED,
        {
            "mode": "recommend",
            "findings_path": "/x",
            "authorized_actions": [],
            "max_actions_per_run": 5,
            "rollback_window_sec": 300,
        },
    )

    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
        ],
    )
    assert result.exit_code == 0, result.output
    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    # Only the promotion.init.applied event drove state — runAsNonRoot at Stage 1.
    assert tracker.file.action_classes[_RUN_AS_ROOT].stage is PromotionStage.STAGE_1


def test_reconcile_chain_inconsistency_surfaces_as_usage_error(tmp_path: Path) -> None:
    """A corrupted chain (advance.applied with from_stage that doesn't
    match the reconstructed state) surfaces as click.UsageError pointing
    at the audit-agent query API for forensics."""
    audit = tmp_path / "audit.jsonl"
    promotion = tmp_path / "promotion.yaml"

    # Write an advance.applied that claims from_stage=2 to a fresh chain
    # where the action class has never been initialised at Stage 2.
    raw_log = AuditLog(audit, agent="remediation", run_id="corrupted-chain-injection")
    from datetime import UTC, datetime

    raw_log.append(
        "promotion.advance.applied",
        {
            "action_type": _RUN_AS_ROOT,
            "event_kind": "advance",
            "operator": "test",
            "timestamp": datetime.now(UTC).isoformat(),
            "reason": "corrupted-chain test",
            "from_stage": 2,  # claims Stage 2 but no prior transition!
            "to_stage": 3,
        },
    )

    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "reconcile",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
        ],
    )
    assert result.exit_code != 0
    assert "chain is inconsistent" in result.output
    assert "audit-agent query" in result.output
