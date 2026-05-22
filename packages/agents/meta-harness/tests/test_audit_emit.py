"""Tests — `meta_harness.audit_emit` (Task 12).

10 tests covering the 4 new v0.2 skill-lifecycle audit emissions:

1.  Action constants are correctly-namespaced ``meta_harness.skill.*``.
2.  ``emit_skill_candidate_emitted`` appends an entry with the full
    payload (skill_id, target_agent, category, shadow_path,
    tool_sequence_hash, emitted_at).
3.  Hash chain preserved across multiple helper calls — each entry's
    ``previous_hash`` is the prior entry's ``entry_hash``.
4.  ``emit_skill_eval_gate_completed`` with ``passed=True``.
5.  ``emit_skill_eval_gate_completed`` with ``passed=False`` (the
    eval-gate emits regardless of verdict).
6.  ``emit_skill_eval_gate_completed`` payload's
    ``per_case_regression_count`` matches the result's tuple length.
7.  ``emit_skill_deployed`` (parametrized OPERATOR_APPROVED +
    AUTO_APPROVED) emits with approval_mode + deployed_path.
8.  ``emit_skill_deployed`` raises ``ValueError`` when
    ``decision.deployed`` is False (routing-bug guard).
9.  ``emit_skill_rejected`` appends with ``rejection_reason``.
10. ``emit_skill_rejected`` raises ``ValueError`` when
    ``decision.deployed`` is True (routing-bug guard).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from charter.audit import AuditLog
from meta_harness.audit_emit import (
    ACTION_SKILL_CANDIDATE_EMITTED,
    ACTION_SKILL_DEPLOYED,
    ACTION_SKILL_EVAL_GATE_COMPLETED,
    ACTION_SKILL_REJECTED,
    emit_skill_candidate_emitted,
    emit_skill_deployed,
    emit_skill_eval_gate_completed,
    emit_skill_rejected,
)
from meta_harness.schemas import (
    DeploymentDecision,
    EvalGateResult,
    Skill,
    SkillApprovalMode,
    SkillCandidate,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)

_AT = datetime(2026, 5, 22, 16, 0, 0, tzinfo=UTC)


def _audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(path=tmp_path / "audit.jsonl", agent="meta_harness", run_id="r_test")


def _candidate() -> SkillCandidate:
    skill = Skill(
        name="aws_iam_privesc_via_assumed_role",
        description="x",
        version="0.1.0",
        platforms=("nexus",),
        target_agent="investigation",
        category="iam-privesc",
        created_by="meta_harness@v0.2.0",
        provenance=(("audit/r.jsonl", "deadbeef"),),
        eval_gate_status=SkillEvalGateStatus.NOT_RUN,
        deployment_status=SkillDeploymentStatus.CANDIDATE,
        body="body",
    )
    return SkillCandidate(
        skill_id="iam-privesc/aws_iam_privesc_via_assumed_role",
        skill=skill,
        shadow_path="/ws/.nexus/candidate-skills/investigation/iam-privesc/aws_iam_privesc_via_assumed_role/SKILL.md",
        tool_sequence_hash="hash_a",
        emitted_at=_AT,
    )


def _eval_gate(*, passed: bool, regressions: tuple[tuple[str, float], ...] = ()) -> EvalGateResult:
    return EvalGateResult(
        skill_id="iam-privesc/aws_iam_privesc_via_assumed_role",
        target_agent="investigation",
        baseline_pass_rate=0.8 if passed else 1.0,
        candidate_pass_rate=0.9 if passed else 0.0,
        per_case_regressions=regressions,
        passed=passed,
        evaluated_at=_AT,
    )


def _decision_deployed(approval_mode: SkillApprovalMode) -> DeploymentDecision:
    return DeploymentDecision(
        skill_id="iam-privesc/aws_iam_privesc_via_assumed_role",
        target_agent="investigation",
        category="iam-privesc",
        deployed=True,
        approval_mode=approval_mode,
        deployed_path="/ws/packages/agents/investigation/src/investigation/nlah/skills/iam-privesc/aws_iam_privesc_via_assumed_role/SKILL.md",
        decided_at=_AT,
    )


def _decision_rejected(reason: str = "eval-gate failed on c1") -> DeploymentDecision:
    return DeploymentDecision(
        skill_id="iam-privesc/aws_iam_privesc_via_assumed_role",
        target_agent="investigation",
        category="iam-privesc",
        deployed=False,
        rejection_reason=reason,
        decided_at=_AT,
    )


def _read_entries(audit_log: AuditLog) -> list[dict[str, object]]:
    return [
        json.loads(line) for line in audit_log.path.read_text("utf-8").splitlines() if line.strip()
    ]


# ---------------------------- action constants ----------------------------


def test_action_constants_are_meta_harness_namespaced() -> None:
    assert ACTION_SKILL_CANDIDATE_EMITTED == "meta_harness.skill.candidate_emitted"
    assert ACTION_SKILL_EVAL_GATE_COMPLETED == "meta_harness.skill.eval_gate_completed"
    assert ACTION_SKILL_DEPLOYED == "meta_harness.skill.deployed"
    assert ACTION_SKILL_REJECTED == "meta_harness.skill.rejected"


# ---------------------------- candidate_emitted ----------------------------


def test_emit_skill_candidate_emitted_appends_full_payload(tmp_path: Path) -> None:
    audit_log = _audit_log(tmp_path)
    cand = _candidate()
    emit_skill_candidate_emitted(audit_log, candidate=cand)
    entries = _read_entries(audit_log)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["action"] == ACTION_SKILL_CANDIDATE_EMITTED
    payload = entry["payload"]
    assert payload["skill_id"] == cand.skill_id
    assert payload["target_agent"] == "investigation"
    assert payload["category"] == "iam-privesc"
    assert payload["shadow_path"] == cand.shadow_path
    assert payload["tool_sequence_hash"] == cand.tool_sequence_hash
    assert payload["emitted_at"] == cand.emitted_at.isoformat()


def test_hash_chain_preserved_across_multiple_helper_calls(tmp_path: Path) -> None:
    """Charter's append-only chain — each subsequent entry's
    ``previous_hash`` must equal the prior entry's ``entry_hash``."""
    audit_log = _audit_log(tmp_path)
    emit_skill_candidate_emitted(audit_log, candidate=_candidate())
    emit_skill_eval_gate_completed(audit_log, result=_eval_gate(passed=True))
    emit_skill_deployed(audit_log, decision=_decision_deployed(SkillApprovalMode.AUTO_APPROVED))
    entries = _read_entries(audit_log)
    assert len(entries) == 3
    assert entries[1]["previous_hash"] == entries[0]["entry_hash"]
    assert entries[2]["previous_hash"] == entries[1]["entry_hash"]


# ---------------------------- eval_gate_completed ----------------------------


def test_emit_skill_eval_gate_completed_passed_true(tmp_path: Path) -> None:
    audit_log = _audit_log(tmp_path)
    emit_skill_eval_gate_completed(audit_log, result=_eval_gate(passed=True))
    entry = _read_entries(audit_log)[0]
    assert entry["action"] == ACTION_SKILL_EVAL_GATE_COMPLETED
    payload = entry["payload"]
    assert payload["passed"] is True
    assert payload["baseline_pass_rate"] == 0.8
    assert payload["candidate_pass_rate"] == 0.9


def test_emit_skill_eval_gate_completed_passed_false_still_emits(tmp_path: Path) -> None:
    """Eval-gate failure also produces an audit entry — Task 13's driver
    needs both passes and failures in the chain for verification."""
    audit_log = _audit_log(tmp_path)
    emit_skill_eval_gate_completed(
        audit_log, result=_eval_gate(passed=False, regressions=(("c1", 100.0),))
    )
    entry = _read_entries(audit_log)[0]
    assert entry["payload"]["passed"] is False


def test_emit_skill_eval_gate_completed_payload_counts_regressions(tmp_path: Path) -> None:
    audit_log = _audit_log(tmp_path)
    emit_skill_eval_gate_completed(
        audit_log,
        result=_eval_gate(
            passed=False,
            regressions=(("c1", 100.0), ("c2", 100.0), ("c3", 100.0)),
        ),
    )
    entry = _read_entries(audit_log)[0]
    assert entry["payload"]["per_case_regression_count"] == 3


# ---------------------------- deployed ----------------------------


@pytest.mark.parametrize(
    "approval_mode",
    [SkillApprovalMode.OPERATOR_APPROVED, SkillApprovalMode.AUTO_APPROVED],
)
def test_emit_skill_deployed_emits_for_both_approval_modes(
    tmp_path: Path, approval_mode: SkillApprovalMode
) -> None:
    audit_log = _audit_log(tmp_path)
    decision = _decision_deployed(approval_mode)
    emit_skill_deployed(audit_log, decision=decision)
    entry = _read_entries(audit_log)[0]
    assert entry["action"] == ACTION_SKILL_DEPLOYED
    payload = entry["payload"]
    assert payload["approval_mode"] == approval_mode.value
    assert payload["deployed_path"] == decision.deployed_path
    assert payload["skill_id"] == decision.skill_id


def test_emit_skill_deployed_raises_on_decision_not_deployed(tmp_path: Path) -> None:
    audit_log = _audit_log(tmp_path)
    with pytest.raises(ValueError, match=r"decision\.deployed=False"):
        emit_skill_deployed(audit_log, decision=_decision_rejected())


# ---------------------------- rejected ----------------------------


def test_emit_skill_rejected_appends_with_rejection_reason(tmp_path: Path) -> None:
    audit_log = _audit_log(tmp_path)
    emit_skill_rejected(audit_log, decision=_decision_rejected("eval-gate failed on c1"))
    entry = _read_entries(audit_log)[0]
    assert entry["action"] == ACTION_SKILL_REJECTED
    payload = entry["payload"]
    assert payload["rejection_reason"] == "eval-gate failed on c1"
    assert payload["skill_id"] == "iam-privesc/aws_iam_privesc_via_assumed_role"


def test_emit_skill_rejected_raises_on_decision_deployed(tmp_path: Path) -> None:
    audit_log = _audit_log(tmp_path)
    with pytest.raises(ValueError, match=r"decision\.deployed=True"):
        emit_skill_rejected(
            audit_log, decision=_decision_deployed(SkillApprovalMode.OPERATOR_APPROVED)
        )
