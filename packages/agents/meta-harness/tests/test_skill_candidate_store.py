"""Tests for ``meta_harness.skill_candidate_store`` (Task 15).

10 tests covering the sidecar metadata layer:

1. ``compute_candidate_meta_path`` returns the expected path layout.
2. ``write_candidate_meta`` writes JSON that ``load_candidate_meta``
   round-trips.
3. ``write_candidate_meta`` creates parent directories on demand.
4. ``load_candidate_meta`` raises ``CandidateNotFoundError`` when no
   sidecar exists.
5. ``find_candidate_by_skill_id`` locates a candidate across multiple
   agent scopes.
6. ``find_candidate_by_skill_id`` raises ``CandidateNotFoundError``
   when no match exists.
7. ``list_pending_candidates`` returns all candidates sorted.
8. ``list_pending_candidates`` returns empty iterator when the
   shadow tree is absent.
9. ``delete_candidate_meta`` removes the sidecar and cleans up empty
   parent directories.
10. ``delete_candidate_meta`` is idempotent — no error when already
    gone.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from meta_harness.schemas import (
    Skill,
    SkillCandidate,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)
from meta_harness.skill_candidate_store import (
    CandidateNotFoundError,
    compute_candidate_meta_path,
    delete_candidate_meta,
    find_candidate_by_skill_id,
    list_pending_candidates,
    load_candidate_meta,
    write_candidate_meta,
)

_EMITTED_AT = datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


def _make_candidate(
    *,
    agent_id: str = "investigation",
    category: str = "iam-privesc",
    name: str = "test_skill",
    tool_sequence_hash: str = "abc123",
) -> SkillCandidate:
    skill = Skill(
        name=name,
        description="Test skill.",
        version="0.1.0",
        platforms=("nexus",),
        target_agent=agent_id,
        category=category,
        created_by="meta_harness@v0.2.0",
        provenance=(),
        eval_gate_status=SkillEvalGateStatus.NOT_RUN,
        deployment_status=SkillDeploymentStatus.CANDIDATE,
        body="Test body.",
    )
    return SkillCandidate(
        skill_id=f"{category}/{name}",
        skill=skill,
        shadow_path=str(
            Path("/ws/.nexus/candidate-skills") / agent_id / f"{category}/{name}" / "SKILL.md"
        ),
        tool_sequence_hash=tool_sequence_hash,
        emitted_at=_EMITTED_AT,
    )


# ------------------------------------------------------------------ path ---


def test_compute_candidate_meta_path_layout() -> None:
    path = compute_candidate_meta_path(
        workspace_root="/ws",
        agent_id="investigation",
        skill_id="iam-privesc/aws_privesc",
    )
    assert path == Path(
        "/ws/.nexus/candidate-skills/investigation/iam-privesc/aws_privesc/candidate_meta.json"
    )


# -------------------------------------------------------------- round-trip ---


def test_write_and_load_round_trip(tmp_path: Path) -> None:
    candidate = _make_candidate()
    write_candidate_meta(candidate, workspace_root=tmp_path)

    loaded = load_candidate_meta(
        workspace_root=tmp_path,
        agent_id="investigation",
        skill_id="iam-privesc/test_skill",
    )
    assert loaded.skill_id == candidate.skill_id
    assert loaded.tool_sequence_hash == candidate.tool_sequence_hash
    assert loaded.emitted_at == candidate.emitted_at
    assert loaded.skill.target_agent == "investigation"


def test_write_creates_parent_dirs(tmp_path: Path) -> None:
    meta_path = compute_candidate_meta_path(
        workspace_root=tmp_path,
        agent_id="investigation",
        skill_id="iam-privesc/novel_skill",
    )
    assert not meta_path.parent.exists()
    write_candidate_meta(_make_candidate(name="novel_skill"), workspace_root=tmp_path)
    assert meta_path.is_file()


# ---------------------------------------------------------------- missing ---


def test_load_raises_when_no_sidecar(tmp_path: Path) -> None:
    with pytest.raises(CandidateNotFoundError, match="candidate sidecar missing"):
        load_candidate_meta(
            workspace_root=tmp_path,
            agent_id="nonexistent",
            skill_id="iam-privesc/nope",
        )


# ------------------------------------------------------------------- find ---


def test_find_candidate_by_skill_id_across_agents(tmp_path: Path) -> None:
    for agent in ("agent_a", "agent_b"):
        write_candidate_meta(
            _make_candidate(agent_id=agent, name=f"skill_for_{agent}"),
            workspace_root=tmp_path,
        )

    found = find_candidate_by_skill_id(
        workspace_root=tmp_path,
        skill_id="iam-privesc/skill_for_agent_b",
    )
    assert found.skill.target_agent == "agent_b"


def test_find_raises_when_no_match(tmp_path: Path) -> None:
    with pytest.raises(CandidateNotFoundError):
        find_candidate_by_skill_id(
            workspace_root=tmp_path,
            skill_id="iam-privesc/nobody",
        )


# -------------------------------------------------------------------- list ---


def test_list_pending_candidates_sorted(tmp_path: Path) -> None:
    candidates = [
        ("agent_b", "skill_b"),
        ("agent_a", "skill_a"),
        ("agent_a", "skill_b"),
    ]
    for agent, name in candidates:
        write_candidate_meta(
            _make_candidate(agent_id=agent, name=name, category="cat"),
            workspace_root=tmp_path,
        )
    result = list(list_pending_candidates(tmp_path))
    assert len(result) == 3
    # Sorted by agent_id then skill_id.
    assert result[0].skill.target_agent == "agent_a"
    assert result[0].skill_id == "cat/skill_a"
    assert result[1].skill.target_agent == "agent_a"
    assert result[1].skill_id == "cat/skill_b"
    assert result[2].skill.target_agent == "agent_b"


def test_list_empty_when_no_shadow_tree(tmp_path: Path) -> None:
    assert list(list_pending_candidates(tmp_path)) == []


# ------------------------------------------------------------------ delete ---


def test_delete_removes_sidecar_and_dirs(tmp_path: Path) -> None:
    write_candidate_meta(_make_candidate(), workspace_root=tmp_path)
    meta_path = compute_candidate_meta_path(
        workspace_root=tmp_path,
        agent_id="investigation",
        skill_id="iam-privesc/test_skill",
    )
    assert meta_path.is_file()

    delete_candidate_meta(
        workspace_root=tmp_path,
        agent_id="investigation",
        skill_id="iam-privesc/test_skill",
    )
    assert not meta_path.is_file()
    assert not meta_path.parent.exists()  # skill dir removed
    assert not meta_path.parent.parent.exists()  # agent dir removed


def test_delete_idempotent(tmp_path: Path) -> None:
    delete_candidate_meta(
        workspace_root=tmp_path,
        agent_id="investigation",
        skill_id="iam-privesc/nope",
    )
    # No exception = pass.
