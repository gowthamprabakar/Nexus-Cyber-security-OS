"""Task 7 CLI tests for the `remediation promotion` subcommand family.

Covers the four operator-facing subcommands:

- `status` — read-only state print.
- `init` — fresh promotion.yaml + audit entry.
- `advance` — sign-off + audit emission + YAML mutation. Rejects skip,
  no-op, and Stage 3 → Stage 4 attempts (the v0.1.1 global gate).
- `demote` — symmetric to advance for downgrades.

The Stage-3 → Stage-4 refusal explicitly cites the two Phase-1c
prerequisites (safety-verification §6 items 3+4). The refusal is the
load-bearing test of this file — a Stage 4 advance MUST NOT succeed
in v0.1.1, regardless of what `--reason` the operator supplies.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from remediation.cli import main
from remediation.promotion import (
    PromotionStage,
    PromotionTracker,
)

_RUN_AS_ROOT = "remediation_k8s_patch_runAsNonRoot"
_RESOURCE_LIMITS = "remediation_k8s_patch_resource_limits"


def _audit_actions(audit_path: Path) -> list[str]:
    """Return the `action` string of every audit entry in `audit_path`."""
    if not audit_path.exists():
        return []
    return [
        json.loads(line)["action"]
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _audit_payloads(audit_path: Path, action: str) -> list[dict]:
    """Return the payloads of all entries with `action == action`."""
    if not audit_path.exists():
        return []
    payloads: list[dict] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        entry = json.loads(line)
        if entry["action"] == action:
            payloads.append(entry["payload"])
    return payloads


# ---------------------------- init ---------------------------------------


def test_init_creates_promotion_yaml_with_default_action_classes(tmp_path: Path) -> None:
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"

    result = CliRunner().invoke(
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
    assert result.exit_code == 0, result.output
    assert promotion.exists()

    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    assert tracker.file.cluster_id == "prod-eu-1"
    # All v0.1 action classes registered at Stage 1.
    assert len(tracker.file.action_classes) == 5
    for entry in tracker.file.action_classes.values():
        assert entry.stage is PromotionStage.STAGE_1

    # Audit emitted `promotion.init.applied` with the cluster_id.
    actions = _audit_actions(audit)
    assert "promotion.init.applied" in actions
    payloads = _audit_payloads(audit, "promotion.init.applied")
    assert payloads[0]["cluster_id"] == "prod-eu-1"
    assert payloads[0]["default_stage"] == 1
    assert len(payloads[0]["action_classes"]) == 5


def test_init_with_custom_action_classes(tmp_path: Path) -> None:
    """The operator can pre-register a subset of action classes."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"

    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "init",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
            "--cluster-id",
            "dev",
            "--action-class",
            _RUN_AS_ROOT,
            "--action-class",
            _RESOURCE_LIMITS,
        ],
    )
    assert result.exit_code == 0, result.output

    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    assert set(tracker.file.action_classes) == {_RUN_AS_ROOT, _RESOURCE_LIMITS}


def test_init_refuses_to_overwrite_existing_file(tmp_path: Path) -> None:
    """Refuses to clobber an existing promotion.yaml — operator must use
    reconcile or delete the file deliberately."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    promotion.write_text("existing content; do not overwrite")

    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "init",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
            "--cluster-id",
            "x",
        ],
    )
    assert result.exit_code != 0
    assert "already exists; refusing to overwrite" in result.output
    assert "reconcile" in result.output
    # Original content untouched.
    assert "existing content" in promotion.read_text()


def test_init_requires_cluster_id(tmp_path: Path) -> None:
    """--cluster-id is required (no auto-generated default)."""
    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "init",
            "--promotion",
            str(tmp_path / "p.yaml"),
            "--audit",
            str(tmp_path / "a.jsonl"),
        ],
    )
    assert result.exit_code != 0
    assert "--cluster-id" in result.output


# ---------------------------- status -------------------------------------


def test_status_on_freshly_initialized_file_shows_stage1(tmp_path: Path) -> None:
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
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

    result = runner.invoke(
        main,
        ["promotion", "status", "--promotion", str(promotion)],
    )
    assert result.exit_code == 0, result.output
    assert "prod-eu-1" in result.output
    assert "STAGE_1" in result.output
    assert _RUN_AS_ROOT in result.output


def test_status_missing_file_exits_nonzero(tmp_path: Path) -> None:
    """Missing promotion.yaml — exit non-zero with init guidance."""
    result = CliRunner().invoke(
        main,
        [
            "promotion",
            "status",
            "--promotion",
            str(tmp_path / "missing.yaml"),
        ],
    )
    # click's `exists=True` constraint fires before the command body.
    assert result.exit_code != 0


def test_status_proposes_promotions_when_evidence_warrants(tmp_path: Path) -> None:
    """A tracker with ≥1 stage1_artifact should be proposed for Stage 1 → Stage 2."""
    from remediation.audit import ACTION_PROMOTION_EVIDENCE_STAGE1
    from remediation.schemas import RemediationActionType

    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
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
            "dev",
            "--action-class",
            _RUN_AS_ROOT,
        ],
    )

    # Inject a Stage-1 artifact via direct tracker mutation.
    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    tracker.record_evidence(
        RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        event=ACTION_PROMOTION_EVIDENCE_STAGE1,
    )
    tracker.save(promotion)

    result = runner.invoke(
        main,
        ["promotion", "status", "--promotion", str(promotion)],
    )
    assert result.exit_code == 0
    assert "Proposed promotions" in result.output
    assert _RUN_AS_ROOT in result.output
    assert "STAGE_1 → STAGE_2" in result.output


# ---------------------------- advance ------------------------------------


def _init(runner: CliRunner, promotion: Path, audit: Path) -> None:
    """Helper: init a fresh promotion.yaml with the default 5 classes."""
    result = runner.invoke(
        main,
        [
            "promotion",
            "init",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
            "--cluster-id",
            "test-cluster",
        ],
    )
    assert result.exit_code == 0, result.output


def test_advance_stage_1_to_2_happy_path(tmp_path: Path) -> None:
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

    result = runner.invoke(
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
            "stage_2",
            "--reason",
            "5 dry-runs passed in staging",
            "--operator",
            "alice",
        ],
    )
    assert result.exit_code == 0, result.output

    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    entry = tracker.file.action_classes[_RUN_AS_ROOT]
    assert entry.stage is PromotionStage.STAGE_2
    assert len(entry.sign_offs) == 1
    assert entry.sign_offs[0].operator == "alice"
    assert entry.sign_offs[0].reason == "5 dry-runs passed in staging"

    # Audit emitted promotion.advance.applied with the sign-off payload.
    payloads = _audit_payloads(audit, "promotion.advance.applied")
    assert len(payloads) == 1
    assert payloads[0]["action_type"] == _RUN_AS_ROOT
    assert payloads[0]["operator"] == "alice"
    assert payloads[0]["from_stage"] == 1
    assert payloads[0]["to_stage"] == 2


def test_advance_refuses_skip_stage(tmp_path: Path) -> None:
    """Stage 1 → Stage 3 is a skip — refused with a remedy message."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

    result = runner.invoke(
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
            "stage_3",
            "--reason",
            "trying to skip",
        ],
    )
    assert result.exit_code != 0
    assert "advance must move exactly +1" in result.output
    assert "stage_2" in result.output  # remedy text names the legal next stage


def test_advance_refuses_no_op(tmp_path: Path) -> None:
    """Stage 1 → Stage 1 (no movement) is refused, but click rejects
    --to stage_1 at the Choice level. So we go via the same-stage path
    by advancing first to Stage 2, then trying to advance again to stage_2."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

    # Move to Stage 2 first.
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
            "stage_2",
            "--reason",
            "step 1",
        ],
    )
    # Now try to advance to Stage 2 again.
    result = runner.invoke(
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
            "stage_2",
            "--reason",
            "duplicate",
        ],
    )
    assert result.exit_code != 0
    assert "already at STAGE_2" in result.output


def test_advance_to_stage_4_refused_with_safety_prerequisites(tmp_path: Path) -> None:
    """**The load-bearing test for Task 7.** Stage 3 → Stage 4 advance is
    refused regardless of the operator's --reason, citing the two
    Phase-1c prerequisites the safety-verification record names. v0.1.1
    holds Stage 4 globally closed."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

    # Advance the action class to Stage 3 first.
    for next_stage in ("stage_2", "stage_3"):
        result = runner.invoke(
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
                "test setup",
            ],
        )
        assert result.exit_code == 0, result.output

    # Attempt Stage 3 → Stage 4 — must refuse.
    result = runner.invoke(
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
            "stage_4",
            "--reason",
            "30 successful runs accumulated",  # operator-provided reason should NOT bypass
        ],
    )
    assert result.exit_code != 0
    assert "Stage 4" in result.output
    # The refusal text names BOTH prerequisites (safety-verification §6 items 3+4).
    assert "rolled-back-path" in result.output
    assert "Stage-3 evidence" in result.output

    # Tracker state unchanged — still Stage 3.
    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    assert tracker.file.action_classes[_RUN_AS_ROOT].stage is PromotionStage.STAGE_3
    # No Stage 4 advance audit entry was written.
    payloads = _audit_payloads(audit, "promotion.advance.applied")
    to_stages = [p["to_stage"] for p in payloads]
    assert 4 not in to_stages, (
        f"Stage 4 advance must not be recorded in the chain; got to_stages={to_stages}"
    )


def test_advance_default_operator_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When --operator is omitted, the operator is derived from
    $NEXUS_OPERATOR or $USER."""
    monkeypatch.setenv("NEXUS_OPERATOR", "operator-from-env")
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

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
            "stage_2",
            "--reason",
            "env-default test",
        ],
    )
    payloads = _audit_payloads(audit, "promotion.advance.applied")
    assert payloads[0]["operator"] == "operator-from-env"


def test_advance_requires_reason(tmp_path: Path) -> None:
    """--reason is required for the audit trail."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

    result = runner.invoke(
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
            "stage_2",
        ],
    )
    assert result.exit_code != 0
    assert "--reason" in result.output


# ---------------------------- demote -------------------------------------


def test_demote_stage_3_to_1_happy_path(tmp_path: Path) -> None:
    """Demote can drop multiple stages in one event (e.g. incident response)."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

    # Advance to Stage 3 first.
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
                "setup",
            ],
        )

    result = runner.invoke(
        main,
        [
            "promotion",
            "demote",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
            "--action",
            _RUN_AS_ROOT,
            "--to",
            "stage_1",
            "--reason",
            "incident #42 — full rollback",
        ],
    )
    assert result.exit_code == 0, result.output

    tracker = PromotionTracker.from_path(promotion)
    assert tracker is not None
    assert tracker.file.action_classes[_RUN_AS_ROOT].stage is PromotionStage.STAGE_1
    # 3 sign-offs: 2 advance + 1 demote.
    assert len(tracker.file.action_classes[_RUN_AS_ROOT].sign_offs) == 3

    payloads = _audit_payloads(audit, "promotion.demote.applied")
    assert len(payloads) == 1
    assert payloads[0]["from_stage"] == 3
    assert payloads[0]["to_stage"] == 1


def test_demote_refuses_non_decrease(tmp_path: Path) -> None:
    """Demote must move to a strictly lower stage. Same-stage / higher-stage refused."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

    # Action class is at Stage 1. Demote to Stage 2 is invalid.
    result = runner.invoke(
        main,
        [
            "promotion",
            "demote",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
            "--action",
            _RUN_AS_ROOT,
            "--to",
            "stage_2",
            "--reason",
            "trying to advance via demote",
        ],
    )
    assert result.exit_code != 0
    assert "strictly lower" in result.output


def test_demote_requires_reason(tmp_path: Path) -> None:
    """--reason is mandatory — incident response audit must be non-empty."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

    # Move to Stage 2 first so we have something to demote.
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
            "stage_2",
            "--reason",
            "setup",
        ],
    )

    result = runner.invoke(
        main,
        [
            "promotion",
            "demote",
            "--promotion",
            str(promotion),
            "--audit",
            str(audit),
            "--action",
            _RUN_AS_ROOT,
            "--to",
            "stage_1",
            # No --reason
        ],
    )
    assert result.exit_code != 0
    assert "--reason" in result.output


def test_advance_audit_chain_is_append_only(tmp_path: Path) -> None:
    """Subsequent advances append to the existing audit chain — chain
    integrity (previous_hash links) is preserved across CLI invocations."""
    promotion = tmp_path / "promotion.yaml"
    audit = tmp_path / "audit.jsonl"
    runner = CliRunner()
    _init(runner, promotion, audit)

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
            "stage_2",
            "--reason",
            "step 1",
        ],
    )
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
            "stage_3",
            "--reason",
            "step 2",
        ],
    )

    actions = _audit_actions(audit)
    # init.applied + 2 advance.applied = 3 entries.
    assert actions.count("promotion.init.applied") == 1
    assert actions.count("promotion.advance.applied") == 2

    # Chain links intact: each non-genesis entry's previous_hash matches
    # the prior entry's entry_hash.
    entries = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line]
    for prev, curr in itertools.pairwise(entries):
        assert curr["previous_hash"] == prev["entry_hash"], f"chain link broken at {curr['action']}"
