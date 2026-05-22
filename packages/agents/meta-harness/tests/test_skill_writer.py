"""Tests — `meta_harness.skill_writer` (Task 7).

13 tests covering the LLM-driven skill compositor:

1.  ``compose_skill_prompt`` is deterministic — same trigger, same bytes.
2.  ``compose_skill_prompt`` includes agent_id, run_id, tool-sequence
    hash, and the full tool-call list.
3.  ``parse_llm_skill_response`` extracts a Skill from valid SKILL.md.
4.  ``parse_llm_skill_response`` overrides ``target_agent`` from the
    trigger (trust boundary — LLM-supplied value is ignored).
5.  ``parse_llm_skill_response`` overrides ``created_by`` to the pinned
    v0.2 value.
6.  ``parse_llm_skill_response`` forces ``deployment_status=candidate``
    and ``eval_gate_status=not_run``.
7.  ``parse_llm_skill_response`` populates ``provenance`` from
    ``trigger.audit_entry_hashes`` paired with ``audit_log_path``.
8.  ``parse_llm_skill_response`` raises ``SkillWriterError`` on
    malformed SKILL.md.
9.  ``parse_llm_skill_response`` raises ``SkillWriterError`` on slug-
    unsafe category / name (path-safety boundary).
10. ``compute_candidate_shadow_path`` returns the Q1 layout exactly.
11. ``write_skill_candidate`` (async) writes SKILL.md and returns a
    candidate with the resolved ``shadow_path``.
12. ``write_skill_candidate`` creates parent directories on demand.
13. **WI-3 byte-equal probe** — same trigger + same FakeLLM response
    → identical SKILL.md bytes across two write invocations.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from meta_harness.schemas import (
    SkillCandidate,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)
from meta_harness.skill_triggers import SkillTrigger
from meta_harness.skill_writer import (
    SkillWriterError,
    compose_skill_prompt,
    compute_candidate_shadow_path,
    parse_llm_skill_response,
    write_skill_candidate,
)

pytestmark = pytest.mark.asyncio

_EMITTED_AT = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)

_LLM_SKILL_MD = """---
name: aws_iam_privesc_via_assumed_role
description: Detect IAM privilege escalation via cross-account role chain.
version: 0.1.0
platforms:
  - nexus
target_agent: SHOULD_BE_OVERRIDDEN
category: iam-privesc
created_by: llm-said-this
provenance: []
eval_gate_status: passed
deployment_status: deployed
---

When you see cross-account AssumeRole chains, follow the chain head-first.
"""


def _trigger(
    *,
    agent_id: str = "investigation",
    run_id: str = "r_42",
    tool_names: tuple[str, ...] = (
        "memory_neighbors_walk",
        "ocsf_lookup",
        "iam_query",
        "s3_get",
        "audit_query",
    ),
    tool_sequence_hash: str = "abc123",
    audit_entry_hashes: tuple[str, ...] = ("h0", "h1", "h2", "h3", "h4"),
) -> SkillTrigger:
    return SkillTrigger(
        agent_id=agent_id,
        run_id=run_id,
        tool_sequence_hash=tool_sequence_hash,
        tool_names=tool_names,
        audit_entry_hashes=audit_entry_hashes,
    )


def _fake_llm(skill_md: str = _LLM_SKILL_MD) -> FakeLLMProvider:
    response = LLMResponse(
        text=skill_md,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=100, output_tokens=200),
        model_pin="claude-sonnet-4-6",
        provider_id="fake",
    )
    return FakeLLMProvider([response])


# ---------------------------- compose_skill_prompt ----------------------------


async def test_compose_skill_prompt_deterministic() -> None:
    trigger = _trigger()
    sys_a, user_a = compose_skill_prompt(trigger)
    sys_b, user_b = compose_skill_prompt(trigger)
    assert sys_a == sys_b
    assert user_a == user_b


async def test_compose_skill_prompt_includes_trigger_fields() -> None:
    trigger = _trigger(agent_id="d.7_investigation", run_id="r_77")
    _, user = compose_skill_prompt(trigger)
    assert "d.7_investigation" in user
    assert "r_77" in user
    assert trigger.tool_sequence_hash in user
    for tool_name in trigger.tool_names:
        assert tool_name in user


# ---------------------------- parse_llm_skill_response ----------------------------


async def test_parse_llm_response_extracts_skill() -> None:
    candidate = parse_llm_skill_response(
        _LLM_SKILL_MD,
        trigger=_trigger(),
        audit_log_path="/ws/.nexus/audit.jsonl",
        workspace_root="/ws",
        emitted_at=_EMITTED_AT,
    )
    assert isinstance(candidate, SkillCandidate)
    assert candidate.skill.name == "aws_iam_privesc_via_assumed_role"
    assert candidate.skill.category == "iam-privesc"
    assert candidate.skill_id == "iam-privesc/aws_iam_privesc_via_assumed_role"
    assert candidate.shadow_path.endswith(
        "/.nexus/candidate-skills/investigation/iam-privesc/aws_iam_privesc_via_assumed_role/SKILL.md"
    )


async def test_parse_llm_response_overrides_target_agent_from_trigger() -> None:
    candidate = parse_llm_skill_response(
        _LLM_SKILL_MD,
        trigger=_trigger(agent_id="investigation"),
        audit_log_path="/ws/audit.jsonl",
        workspace_root="/ws",
        emitted_at=_EMITTED_AT,
    )
    assert candidate.skill.target_agent == "investigation"


async def test_parse_llm_response_overrides_created_by() -> None:
    candidate = parse_llm_skill_response(
        _LLM_SKILL_MD,
        trigger=_trigger(),
        audit_log_path="/ws/audit.jsonl",
        workspace_root="/ws",
        emitted_at=_EMITTED_AT,
    )
    assert candidate.skill.created_by == "meta_harness@v0.2.0"


async def test_parse_llm_response_forces_candidate_and_not_run_statuses() -> None:
    candidate = parse_llm_skill_response(
        _LLM_SKILL_MD,
        trigger=_trigger(),
        audit_log_path="/ws/audit.jsonl",
        workspace_root="/ws",
        emitted_at=_EMITTED_AT,
    )
    assert candidate.skill.deployment_status == SkillDeploymentStatus.CANDIDATE
    assert candidate.skill.eval_gate_status == SkillEvalGateStatus.NOT_RUN


async def test_parse_llm_response_provenance_pairs_audit_log_with_each_entry_hash() -> None:
    trigger = _trigger(audit_entry_hashes=("h_a", "h_b", "h_c"))
    candidate = parse_llm_skill_response(
        _LLM_SKILL_MD,
        trigger=trigger,
        audit_log_path="/ws/.nexus/audit.jsonl",
        workspace_root="/ws",
        emitted_at=_EMITTED_AT,
    )
    assert candidate.skill.provenance == (
        ("/ws/.nexus/audit.jsonl", "h_a"),
        ("/ws/.nexus/audit.jsonl", "h_b"),
        ("/ws/.nexus/audit.jsonl", "h_c"),
    )


async def test_parse_llm_response_raises_on_malformed_skill_md() -> None:
    with pytest.raises(SkillWriterError, match=r"malformed SKILL\.md"):
        parse_llm_skill_response(
            "# no frontmatter at all",
            trigger=_trigger(),
            audit_log_path="/ws/audit.jsonl",
            workspace_root="/ws",
            emitted_at=_EMITTED_AT,
        )


async def test_parse_llm_response_raises_on_slug_unsafe_category() -> None:
    bad = _LLM_SKILL_MD.replace("category: iam-privesc", "category: IAM Privesc!")
    with pytest.raises(SkillWriterError, match="category is not slug-safe"):
        parse_llm_skill_response(
            bad,
            trigger=_trigger(),
            audit_log_path="/ws/audit.jsonl",
            workspace_root="/ws",
            emitted_at=_EMITTED_AT,
        )


# ---------------------------- compute_candidate_shadow_path ----------------------------


async def test_compute_candidate_shadow_path_layout(tmp_path: Path) -> None:
    path = compute_candidate_shadow_path(
        workspace_root=tmp_path,
        agent_id="investigation",
        skill_id="iam-privesc/role-chain",
    )
    assert (
        path
        == tmp_path
        / ".nexus"
        / "candidate-skills"
        / "investigation"
        / "iam-privesc"
        / "role-chain"
        / "SKILL.md"
    )


# ---------------------------- write_skill_candidate (async) ----------------------------


async def test_write_skill_candidate_writes_to_shadow_path(tmp_path: Path) -> None:
    trigger = _trigger()
    candidate = await write_skill_candidate(
        trigger=trigger,
        audit_log_path=str(tmp_path / ".nexus" / "audit.jsonl"),
        workspace_root=tmp_path,
        llm_provider=_fake_llm(),
        emitted_at=_EMITTED_AT,
    )
    assert candidate.shadow_path.endswith(
        "/.nexus/candidate-skills/investigation/iam-privesc/aws_iam_privesc_via_assumed_role/SKILL.md"
    )
    on_disk = Path(candidate.shadow_path).read_text(encoding="utf-8")
    assert "aws_iam_privesc_via_assumed_role" in on_disk
    assert "cross-account AssumeRole" in on_disk


async def test_write_skill_candidate_creates_parent_dirs(tmp_path: Path) -> None:
    deep_root = tmp_path / "deep" / "nested" / "workspace"
    deep_root.mkdir(parents=True)
    candidate = await write_skill_candidate(
        trigger=_trigger(),
        audit_log_path=str(deep_root / "audit.jsonl"),
        workspace_root=deep_root,
        llm_provider=_fake_llm(),
        emitted_at=_EMITTED_AT,
    )
    assert Path(candidate.shadow_path).is_file()


async def test_write_skill_candidate_byte_equal_under_same_stub_response(tmp_path: Path) -> None:
    """WI-3: identical trigger + identical FakeLLM response → identical bytes on disk."""
    trigger = _trigger()
    audit_log_path = str(tmp_path / "audit.jsonl")

    ws_a = tmp_path / "a"
    ws_b = tmp_path / "b"
    ws_a.mkdir()
    ws_b.mkdir()

    cand_a = await write_skill_candidate(
        trigger=trigger,
        audit_log_path=audit_log_path,
        workspace_root=ws_a,
        llm_provider=_fake_llm(),
        emitted_at=_EMITTED_AT,
    )
    cand_b = await write_skill_candidate(
        trigger=trigger,
        audit_log_path=audit_log_path,
        workspace_root=ws_b,
        llm_provider=_fake_llm(),
        emitted_at=_EMITTED_AT,
    )
    bytes_a = Path(cand_a.shadow_path).read_bytes()
    bytes_b = Path(cand_b.shadow_path).read_bytes()
    assert bytes_a == bytes_b
