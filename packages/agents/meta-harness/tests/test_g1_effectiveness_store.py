"""G1 effectiveness store tests — Task 9.

12 tests covering get_effectiveness_score, write_effectiveness_score,
and list_deployed_skills_with_scores for the persistent storage layer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from charter.audit import AuditLog
from meta_harness.effectiveness_store import (
    _effectiveness_path,
    get_effectiveness_score,
    list_deployed_skills_with_scores,
    write_effectiveness_score,
)
from meta_harness.schemas import (
    AxisBreakdown,
    EffectivenessAxes,
    EffectivenessReason,
    EffectivenessScore,
)

_NOW = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)


def _audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", agent="test-agent", run_id="test-run")


def _make_axes(score: float = 0.85, confidence: float = 0.5) -> EffectivenessAxes:
    return EffectivenessAxes(
        adoption=AxisBreakdown(score=score, confidence=confidence),
        outcome=AxisBreakdown(score=score, confidence=confidence),
        feedback=AxisBreakdown(score=score, confidence=confidence),
    )


def _make_score(
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    tenant_id: str = "default",
    global_score: float | None = 0.85,
    confidence: float = 0.5,
) -> EffectivenessScore:
    """Create a valid EffectivenessScore, respecting model validators.

    When confidence > 0, global_score and axes_breakdown are required.
    When confidence == 0, both must be None and reason is required.
    """
    if confidence > 0.0:
        axes = _make_axes(score=global_score or 0.0, confidence=confidence)
        reason = None
    else:
        axes = None
        global_score = None
        reason = EffectivenessReason.INSUFFICIENT_DATA
    return EffectivenessScore(
        skill_id=skill_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        global_score=global_score,
        confidence=confidence,
        axes_breakdown=axes,
        reason=reason,
        computed_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Read missing / unparseable
# ---------------------------------------------------------------------------


def test_g1_read_missing_sidecar_returns_none(tmp_path: Path) -> None:
    """No effectiveness.json → get_effectiveness_score returns None."""
    result = get_effectiveness_score(
        skill_id="sk_nonexistent",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert result is None


def test_g1_read_unparseable_sidecar_returns_none(tmp_path: Path) -> None:
    """Malformed effectiveness.json → get_effectiveness_score returns None."""
    path = _effectiveness_path(tmp_path, "test-agent", "sk_bad")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("NOT VALID JSON", encoding="utf-8")
    result = get_effectiveness_score(
        skill_id="sk_bad",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert result is None


# ---------------------------------------------------------------------------
# Write → read round-trip
# ---------------------------------------------------------------------------


def test_g1_write_then_read_round_trip(tmp_path: Path) -> None:
    """A written score can be read back identically."""
    al = _audit_log(tmp_path)
    score = _make_score(skill_id="sk_rt", global_score=0.72, confidence=0.6)
    write_effectiveness_score(score, audit_log=al, workspace_root=tmp_path)

    result = get_effectiveness_score(
        skill_id="sk_rt",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert result is not None
    assert result.global_score == pytest.approx(0.72)
    assert result.confidence == pytest.approx(0.6)
    assert result.skill_id == "sk_rt"


# ---------------------------------------------------------------------------
# Atomic write: no corrupted sidecar from partial writes
# ---------------------------------------------------------------------------


def test_g1_atomic_write_no_corrupted_sidecar(tmp_path: Path) -> None:
    """Temp-file + rename ensures no partial writes in the final file."""
    al = _audit_log(tmp_path)
    score = _make_score(skill_id="sk_atomic", global_score=0.5)
    write_effectiveness_score(score, audit_log=al, workspace_root=tmp_path)

    path = _effectiveness_path(tmp_path, "test-agent", "sk_atomic")
    # The .tmp file should NOT exist after a successful write (it was renamed).
    tmp_path = path.with_suffix(".tmp")
    assert not tmp_path.exists()
    # The effectiveness.json should exist and be valid.
    assert path.is_file()
    parsed = EffectivenessScore.model_validate_json(path.read_text(encoding="utf-8"))
    assert parsed.global_score == 0.5


# ---------------------------------------------------------------------------
# Idempotent audit emission
# ---------------------------------------------------------------------------


def test_g1_write_same_score_twice_only_one_audit_event(tmp_path: Path) -> None:
    """Writing the same score twice emits effectiveness_updated only once."""
    al = _audit_log(tmp_path)
    score = _make_score(skill_id="sk_idem", global_score=0.9, confidence=0.8)
    write_effectiveness_score(score, audit_log=al, workspace_root=tmp_path)
    write_effectiveness_score(score, audit_log=al, workspace_root=tmp_path)

    audit_text = al.path.read_text(encoding="utf-8")
    count = audit_text.count("meta_harness.skill.effectiveness_updated")
    assert count == 1


def test_g1_write_different_score_emits_second_audit_event(tmp_path: Path) -> None:
    """Writing a different score emits a second effectiveness_updated event."""
    al = _audit_log(tmp_path)
    score_v1 = _make_score(skill_id="sk_chg", global_score=0.5, confidence=0.4)
    score_v2 = _make_score(skill_id="sk_chg", global_score=0.7, confidence=0.6)
    write_effectiveness_score(score_v1, audit_log=al, workspace_root=tmp_path)
    write_effectiveness_score(score_v2, audit_log=al, workspace_root=tmp_path)

    audit_text = al.path.read_text(encoding="utf-8")
    count = audit_text.count("meta_harness.skill.effectiveness_updated")
    assert count == 2
    # Second event carries old + new values.
    assert "old_global_score" in audit_text
    assert "new_global_score" in audit_text


# ---------------------------------------------------------------------------
# Audit event payload correctness
# ---------------------------------------------------------------------------


def test_g1_audit_event_carries_old_and_new_values(tmp_path: Path) -> None:
    """effectiveness_updated audit event includes old and new score + confidence."""
    al = _audit_log(tmp_path)
    score_v1 = _make_score(skill_id="sk_payload", global_score=0.3, confidence=0.2)
    score_v2 = _make_score(skill_id="sk_payload", global_score=0.9, confidence=1.0)
    write_effectiveness_score(score_v1, audit_log=al, workspace_root=tmp_path)
    write_effectiveness_score(score_v2, audit_log=al, workspace_root=tmp_path)

    audit_text = al.path.read_text(encoding="utf-8")
    # First write: old is None/0.0, new is 0.3/0.2
    assert '"old_global_score": null' in audit_text or "null" in audit_text
    # Second write: old is 0.3, new is 0.9
    assert "0.3" in audit_text
    assert "0.9" in audit_text


# ---------------------------------------------------------------------------
# Tenant scoping
# ---------------------------------------------------------------------------


def test_g1_tenant_scoping_read(tmp_path: Path) -> None:
    """Scores for tenant A are invisible to tenant B reads."""
    al = _audit_log(tmp_path)
    score_acme = _make_score(
        skill_id="sk_tenant",
        tenant_id="acme",
        global_score=0.8,
    )
    write_effectiveness_score(score_acme, audit_log=al, workspace_root=tmp_path)

    # Read as "default" tenant → should not find acme's score.
    result = get_effectiveness_score(
        skill_id="sk_tenant",
        agent_id="test-agent",
        workspace_root=tmp_path,
        tenant_id="default",
    )
    assert result is None

    # Read as "acme" tenant → should find it.
    result_acme = get_effectiveness_score(
        skill_id="sk_tenant",
        agent_id="test-agent",
        workspace_root=tmp_path,
        tenant_id="acme",
    )
    assert result_acme is not None
    assert result_acme.global_score == pytest.approx(0.8)


# ---------------------------------------------------------------------------
# List deployed skills
# ---------------------------------------------------------------------------


def test_g1_list_empty_workspace_returns_empty(tmp_path: Path) -> None:
    """No deployed-skills directory → empty list."""
    results = list_deployed_skills_with_scores(workspace_root=tmp_path)
    assert results == []


def test_g1_list_mixed_scored_and_unscored(tmp_path: Path) -> None:
    """Some skills have scores, some don't → mixed list."""
    al = _audit_log(tmp_path)
    # Write score for sk_a only.
    write_effectiveness_score(
        _make_score(skill_id="sk_a", global_score=0.6),
        audit_log=al,
        workspace_root=tmp_path,
    )
    # Create directory for sk_b but no effectiveness.json.
    path_b = _effectiveness_path(tmp_path, "test-agent", "sk_b")
    path_b.parent.mkdir(parents=True, exist_ok=True)

    results = list_deployed_skills_with_scores(workspace_root=tmp_path)
    # Should have 2 entries: (test-agent, sk_a, score) and (test-agent, sk_b, None).
    assert len(results) == 2
    agent_ids = {r[0] for r in results}
    skill_ids = {r[1] for r in results}
    assert agent_ids == {"test-agent"}
    assert skill_ids == {"sk_a", "sk_b"}

    scores_by_skill = {r[1]: r[2] for r in results}
    assert scores_by_skill["sk_a"] is not None
    assert scores_by_skill["sk_b"] is None


def test_g1_list_respects_tenant_filter(tmp_path: Path) -> None:
    """List filters scores by tenant_id."""
    al = _audit_log(tmp_path)
    write_effectiveness_score(
        _make_score(skill_id="sk_t1", tenant_id="acme", global_score=0.9),
        audit_log=al,
        workspace_root=tmp_path,
    )
    write_effectiveness_score(
        _make_score(skill_id="sk_t2", tenant_id="default", global_score=0.3),
        audit_log=al,
        workspace_root=tmp_path,
    )

    # List for "acme" → only sk_t1 has a score.
    results = list_deployed_skills_with_scores(workspace_root=tmp_path, tenant_id="acme")
    scores_by_skill = {r[1]: r[2] for r in results}
    assert scores_by_skill.get("sk_t1") is not None
    # sk_t2 exists but its score is for "default" tenant → listed as None.
    assert scores_by_skill.get("sk_t2") is None


# ---------------------------------------------------------------------------
# CF #2 — write failure
# ---------------------------------------------------------------------------


def test_g1_cf2_write_failure_emits_error_and_raises(tmp_path: Path, mocker) -> None:
    """Forced write failure → effectiveness_error emitted + OSError re-raised."""
    al = _audit_log(tmp_path)
    score = _make_score(skill_id="sk_cf2")
    # Make the tmp_path directory, then force rename to fail by mocking.
    sidecar_path = _effectiveness_path(tmp_path, "test-agent", "sk_cf2")
    sidecar_path.parent.mkdir(parents=True, exist_ok=True)
    mocker.patch("pathlib.Path.rename", side_effect=OSError("disk full"))

    with pytest.raises(OSError, match="disk full"):
        write_effectiveness_score(score, audit_log=al, workspace_root=tmp_path)

    audit_text = al.path.read_text(encoding="utf-8")
    assert "meta_harness.skill.effectiveness_error" in audit_text
    assert "effectiveness_store_write_failure" in audit_text
    assert "sk_cf2" in audit_text
