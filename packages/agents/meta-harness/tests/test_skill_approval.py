"""Tests — `meta_harness.skill_approval` (Task 10).

10 tests covering the file-based approval workflow:

1.  ``compute_canonical_skill_path`` returns the bundled NLAH layout.
2.  ``compute_notification_path`` flattens skill_id ``/`` → ``__``.
3.  ``write_candidate_notification`` creates the markdown with the
    operator-relevant fields + CLI commands.
4.  ``decide_auto_deployable`` returns ``AUTO_APPROVED`` when eval-
    gate passed + class registered.
5.  ``decide_auto_deployable`` returns ``None`` when eval-gate
    passed + class is new (operator approval required).
6.  ``decide_auto_deployable`` raises ``SkillApprovalError`` when the
    eval-gate failed (caller must reject directly).
7.  ``approve_candidate`` first-of-class: writes canonical SKILL.md
    with ``deployment_status=DEPLOYED``, removes shadow, registers
    class, returns ``OPERATOR_APPROVED`` ``DeploymentDecision``.
8.  ``auto_deploy_candidate`` refinement path: promotes shadow → canonical
    + records deployment + returns ``AUTO_APPROVED`` decision.
9.  ``auto_deploy_candidate`` raises ``SkillApprovalError`` when the
    class isn't registered (defends against wrong routing).
10. ``reject_candidate`` removes the shadow file + returns a
    ``DeploymentDecision(deployed=False, rejection_reason=...)``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from meta_harness.schemas import (
    EvalGateResult,
    Skill,
    SkillApprovalMode,
    SkillCandidate,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)
from meta_harness.skill_approval import (
    SkillApprovalError,
    approve_candidate,
    auto_deploy_candidate,
    compute_canonical_skill_path,
    compute_notification_path,
    decide_auto_deployable,
    reject_candidate,
    write_candidate_notification,
)
from meta_harness.skill_format import parse_skill_md
from meta_harness.skill_registry import (
    SkillClassRegistry,
    register_class,
)

_DECIDED_AT = datetime(2026, 5, 22, 14, 0, 0, tzinfo=UTC)
_EMITTED_AT = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)


def _make_candidate(
    *,
    workspace_root: Path,
    agent_id: str = "investigation",
    category: str = "iam-privesc",
    name: str = "aws_iam_privesc_via_assumed_role",
    skill_id: str | None = None,
) -> SkillCandidate:
    resolved_skill_id = skill_id if skill_id is not None else f"{category}/{name}"
    shadow_path = (
        workspace_root / ".nexus" / "candidate-skills" / agent_id / resolved_skill_id / "SKILL.md"
    )
    shadow_path.parent.mkdir(parents=True, exist_ok=True)
    skill = Skill(
        name=name,
        description="Detect IAM privilege escalation via cross-account role chain.",
        version="0.1.0",
        platforms=("nexus",),
        target_agent=agent_id,
        category=category,
        created_by="meta_harness@v0.2.0",
        provenance=(("audit/r.jsonl", "deadbeef"),),
        eval_gate_status=SkillEvalGateStatus.PASSED,
        deployment_status=SkillDeploymentStatus.CANDIDATE,
        body="Walk the role-chain head-first when you see cross-account AssumeRole.",
    )
    candidate = SkillCandidate(
        skill_id=resolved_skill_id,
        skill=skill,
        shadow_path=str(shadow_path),
        tool_sequence_hash="hash_a",
        emitted_at=_EMITTED_AT,
    )
    # Seed the shadow file so promotion can remove it.
    shadow_path.write_text("# placeholder shadow SKILL.md\n", encoding="utf-8")
    return candidate


def _eval_gate(passed: bool = True) -> EvalGateResult:
    return EvalGateResult(
        skill_id="iam-privesc/aws_iam_privesc_via_assumed_role",
        target_agent="investigation",
        baseline_pass_rate=0.8 if passed else 1.0,
        candidate_pass_rate=0.9 if passed else 0.0,
        per_case_regressions=() if passed else (("c1", 100.0),),
        passed=passed,
        evaluated_at=_DECIDED_AT,
    )


# ---------------------------- path helpers ----------------------------


def test_compute_canonical_skill_path_layout(tmp_path: Path) -> None:
    assert (
        compute_canonical_skill_path(
            workspace_root=tmp_path,
            agent_id="investigation",
            skill_id="iam-privesc/role-chain",
        )
        == tmp_path
        / "packages"
        / "agents"
        / "investigation"
        / "src"
        / "investigation"
        / "nlah"
        / "skills"
        / "iam-privesc"
        / "role-chain"
        / "SKILL.md"
    )


def test_compute_notification_path_flattens_skill_id_slash(tmp_path: Path) -> None:
    assert (
        compute_notification_path(tmp_path, "iam-privesc/role-chain")
        == tmp_path / "skill_candidate_iam-privesc__role-chain.md"
    )


# ---------------------------- write_candidate_notification ----------------------------


def test_write_candidate_notification_includes_required_fields(tmp_path: Path) -> None:
    candidate = _make_candidate(workspace_root=tmp_path)
    path = write_candidate_notification(
        candidate=candidate,
        eval_gate=_eval_gate(passed=True),
        workspace_root=tmp_path,
    )
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert candidate.skill_id in text
    assert "investigation" in text
    assert "iam-privesc" in text
    assert "meta-harness approve-skill" in text
    assert "meta-harness reject-skill" in text


# ---------------------------- decide_auto_deployable ----------------------------


def test_decide_auto_deployable_registered_class_returns_auto_approved(tmp_path: Path) -> None:
    candidate = _make_candidate(workspace_root=tmp_path)
    registry = register_class(
        SkillClassRegistry(),
        agent_id=candidate.skill.target_agent,
        category=candidate.skill.category,
        skill_id="iam-privesc/seed-skill",
        tool_sequence_hash="hash_seed",
        approved_at=_DECIDED_AT,
    )
    mode = decide_auto_deployable(
        candidate=candidate,
        registry=registry,
        eval_gate=_eval_gate(passed=True),
    )
    assert mode == SkillApprovalMode.AUTO_APPROVED


def test_decide_auto_deployable_new_class_returns_none(tmp_path: Path) -> None:
    candidate = _make_candidate(workspace_root=tmp_path)
    mode = decide_auto_deployable(
        candidate=candidate,
        registry=SkillClassRegistry(),
        eval_gate=_eval_gate(passed=True),
    )
    assert mode is None


def test_decide_auto_deployable_eval_gate_failed_raises(tmp_path: Path) -> None:
    candidate = _make_candidate(workspace_root=tmp_path)
    with pytest.raises(SkillApprovalError, match="failed eval-gate"):
        decide_auto_deployable(
            candidate=candidate,
            registry=SkillClassRegistry(),
            eval_gate=_eval_gate(passed=False),
        )


# ---------------------------- approve / auto-deploy / reject ----------------------------


def test_approve_candidate_first_of_class_promotes_and_registers(tmp_path: Path) -> None:
    candidate = _make_candidate(workspace_root=tmp_path)
    decision, new_registry = approve_candidate(
        candidate,
        registry=SkillClassRegistry(),
        workspace_root=tmp_path,
        decided_at=_DECIDED_AT,
    )
    assert decision.deployed is True
    assert decision.approval_mode == SkillApprovalMode.OPERATOR_APPROVED
    assert decision.deployed_path is not None
    canonical_path = Path(decision.deployed_path)
    assert canonical_path.is_file()
    # Shadow removed
    assert not Path(candidate.shadow_path).is_file()
    # Canonical file carries deployment_status=deployed (round-trip)
    deployed_skill = parse_skill_md(canonical_path)
    assert deployed_skill.deployment_status == SkillDeploymentStatus.DEPLOYED
    # Class registered
    assert new_registry.is_class_registered("investigation", "iam-privesc")


def test_auto_deploy_candidate_refinement_records_deployment(tmp_path: Path) -> None:
    # Seed registry with existing class
    registry = register_class(
        SkillClassRegistry(),
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/seed-skill",
        tool_sequence_hash="hash_seed",
        approved_at=_DECIDED_AT,
    )
    candidate = _make_candidate(workspace_root=tmp_path)
    decision, new_registry = auto_deploy_candidate(
        candidate,
        registry=registry,
        workspace_root=tmp_path,
        decided_at=_DECIDED_AT,
    )
    assert decision.deployed is True
    assert decision.approval_mode == SkillApprovalMode.AUTO_APPROVED
    # Refinement recorded in the class entry
    entry = new_registry.entry_for("investigation", "iam-privesc")
    assert entry is not None
    assert candidate.skill_id in entry.deployed_skill_ids
    assert candidate.tool_sequence_hash in entry.deployed_tool_sequence_hashes


def test_auto_deploy_candidate_unregistered_class_raises(tmp_path: Path) -> None:
    candidate = _make_candidate(workspace_root=tmp_path)
    with pytest.raises(SkillApprovalError, match="unregistered class"):
        auto_deploy_candidate(
            candidate,
            registry=SkillClassRegistry(),
            workspace_root=tmp_path,
            decided_at=_DECIDED_AT,
        )


def test_reject_candidate_removes_shadow_and_returns_rejected_decision(tmp_path: Path) -> None:
    candidate = _make_candidate(workspace_root=tmp_path)
    assert Path(candidate.shadow_path).is_file()
    decision = reject_candidate(
        candidate,
        rejection_reason="eval-gate failed: per-case regression on c1",
        decided_at=_DECIDED_AT,
    )
    assert decision.deployed is False
    assert decision.approval_mode is None
    assert decision.deployed_path is None
    assert decision.rejection_reason is not None
    assert "eval-gate failed" in decision.rejection_reason
    assert not Path(candidate.shadow_path).is_file()
