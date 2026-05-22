"""Tests — `meta_harness.schemas` v0.2 extensions (Task 2).

15 tests covering the 5 new skill-lifecycle pydantic types:

- ``SkillClassKey`` — composite key with ``as_key()`` serialisation.
- ``Skill`` — agentskills.io + Nexus frontmatter; platforms +
  provenance validation; ``class_key`` property.
- ``SkillCandidate`` — shadow-path artefact; deployment_status must
  be ``candidate``.
- ``EvalGateResult`` — eval-gate outcome with per-case regressions
  + ``overall_drop_pct`` property.
- ``DeploymentDecision`` — XOR validation: deployed=True requires
  approval_mode + deployed_path; deployed=False requires
  rejection_reason.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from meta_harness.schemas import (
    DeploymentDecision,
    EvalGateResult,
    Skill,
    SkillApprovalMode,
    SkillCandidate,
    SkillClassKey,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)
from pydantic import ValidationError

_NOW = datetime(2026, 5, 22, 12, 0, tzinfo=UTC)


def _skill(**overrides: object) -> Skill:
    """Build a Skill with sensible v0.2 defaults."""
    defaults: dict[str, object] = {
        "name": "aws_iam_privesc_via_assumed_role",
        "description": "Detect IAM privilege escalation via cross-account role chain.",
        "version": "0.1.0",
        "platforms": ("nexus",),
        "target_agent": "investigation",
        "category": "iam-privesc",
        "created_by": "meta_harness@v0.2.0",
        "provenance": (("audit/r_eval.jsonl", "deadbeefcafebabe"),),
        "eval_gate_status": SkillEvalGateStatus.NOT_RUN,
        "deployment_status": SkillDeploymentStatus.CANDIDATE,
        "body": "When you see cross-account AssumeRole chains, ...",
    }
    defaults.update(overrides)
    return Skill(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# SkillClassKey
# ---------------------------------------------------------------------------


def test_skill_class_key_as_key_format() -> None:
    key = SkillClassKey(agent_id="investigation", category="iam-privesc")
    assert key.as_key() == "investigation:iam-privesc"


def test_skill_class_key_rejects_empty_components() -> None:
    with pytest.raises(ValidationError):
        SkillClassKey(agent_id="", category="x")
    with pytest.raises(ValidationError):
        SkillClassKey(agent_id="x", category="")


# ---------------------------------------------------------------------------
# Skill
# ---------------------------------------------------------------------------


def test_skill_minimal_valid() -> None:
    skill = _skill()
    assert skill.name == "aws_iam_privesc_via_assumed_role"
    assert skill.target_agent == "investigation"
    assert skill.eval_gate_status == SkillEvalGateStatus.NOT_RUN
    assert skill.deployment_status == SkillDeploymentStatus.CANDIDATE


def test_skill_class_key_property() -> None:
    skill = _skill(target_agent="cloud_posture", category="s3-policy")
    assert skill.class_key.as_key() == "cloud_posture:s3-policy"


def test_skill_platforms_must_be_non_empty() -> None:
    with pytest.raises(ValidationError, match="at least one entry"):
        _skill(platforms=())


def test_skill_platform_entry_bounded() -> None:
    with pytest.raises(ValidationError, match="exceeds"):
        _skill(platforms=("x" * 64,))


def test_skill_provenance_pair_shape() -> None:
    """Each provenance entry MUST be a (audit_log_path, entry_hash) 2-tuple."""
    skill = _skill(
        provenance=(
            ("audit/r1.jsonl", "hash1"),
            ("audit/r2.jsonl", "hash2"),
        ),
    )
    assert len(skill.provenance) == 2


def test_skill_provenance_rejects_empty_path() -> None:
    with pytest.raises(ValidationError, match="audit_log_path"):
        _skill(provenance=(("", "hash1"),))


def test_skill_provenance_rejects_empty_hash() -> None:
    with pytest.raises(ValidationError, match="entry_hash"):
        _skill(provenance=(("audit/r1.jsonl", ""),))


# ---------------------------------------------------------------------------
# SkillCandidate
# ---------------------------------------------------------------------------


def test_skill_candidate_valid_when_deployment_status_is_candidate() -> None:
    candidate = SkillCandidate(
        skill_id="skill_abc",
        skill=_skill(),
        shadow_path="/ws/.nexus/candidate-skills/investigation/iam-privesc/skill_abc/SKILL.md",
        tool_sequence_hash="abc123",
        emitted_at=_NOW,
    )
    assert candidate.skill.deployment_status == SkillDeploymentStatus.CANDIDATE


def test_skill_candidate_rejects_non_candidate_deployment_status() -> None:
    deployed_skill = _skill(deployment_status=SkillDeploymentStatus.DEPLOYED)
    with pytest.raises(ValidationError, match="candidate"):
        SkillCandidate(
            skill_id="skill_abc",
            skill=deployed_skill,
            shadow_path="/ws/shadow/SKILL.md",
            tool_sequence_hash="abc123",
            emitted_at=_NOW,
        )


# ---------------------------------------------------------------------------
# EvalGateResult
# ---------------------------------------------------------------------------


def test_eval_gate_result_overall_drop_pct() -> None:
    result = EvalGateResult(
        skill_id="skill_abc",
        target_agent="investigation",
        baseline_pass_rate=0.90,
        candidate_pass_rate=0.85,
        per_case_regressions=(("case_03", 5.0),),
        passed=False,
        evaluated_at=_NOW,
    )
    assert result.overall_drop_pct == pytest.approx(5.0)


def test_eval_gate_result_pass_rate_bounds() -> None:
    with pytest.raises(ValidationError):
        EvalGateResult(
            skill_id="x",
            target_agent="y",
            baseline_pass_rate=1.5,  # out of [0, 1]
            candidate_pass_rate=0.5,
            passed=False,
            evaluated_at=_NOW,
        )


# ---------------------------------------------------------------------------
# DeploymentDecision
# ---------------------------------------------------------------------------


def test_deployment_decision_deployed_requires_approval_mode_and_path() -> None:
    decision = DeploymentDecision(
        skill_id="x",
        target_agent="y",
        category="z",
        deployed=True,
        approval_mode=SkillApprovalMode.AUTO_APPROVED,
        deployed_path="/ws/repo/.../SKILL.md",
        decided_at=_NOW,
    )
    assert decision.deployed is True
    assert decision.approval_mode == SkillApprovalMode.AUTO_APPROVED
    assert decision.rejection_reason is None


def test_deployment_decision_deployed_rejects_missing_approval_mode() -> None:
    with pytest.raises(ValidationError, match="approval_mode"):
        DeploymentDecision(
            skill_id="x",
            target_agent="y",
            category="z",
            deployed=True,
            deployed_path="/ws/repo/.../SKILL.md",
            decided_at=_NOW,
        )


def test_deployment_decision_rejected_requires_reason() -> None:
    decision = DeploymentDecision(
        skill_id="x",
        target_agent="y",
        category="z",
        deployed=False,
        rejection_reason="eval-gate failed: per-case drop 7.5% on case_03",
        decided_at=_NOW,
    )
    assert decision.deployed is False
    assert decision.approval_mode is None
    assert decision.deployed_path is None


def test_deployment_decision_rejected_forbids_approval_fields() -> None:
    with pytest.raises(ValidationError, match="approval_mode"):
        DeploymentDecision(
            skill_id="x",
            target_agent="y",
            category="z",
            deployed=False,
            approval_mode=SkillApprovalMode.AUTO_APPROVED,
            rejection_reason="...",
            decided_at=_NOW,
        )
