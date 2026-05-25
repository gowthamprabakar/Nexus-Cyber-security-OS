"""G1 composite effectiveness score tests — Task 8.

12 tests covering compute_effectiveness_score across all three axes:
adoption, outcome, and feedback combined via confidence-weighted Q9 formula.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from charter.audit import AuditLog
from meta_harness.schemas import EffectivenessReason
from meta_harness.skill_adoption import _sidecar_path
from meta_harness.skill_effectiveness import compute_effectiveness_score
from meta_harness.skill_feedback import _operator_ratings_path

_NOW = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)
_TS_COUNTER = count()


def _audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", agent="test-agent", run_id="test-run")


# ---------------------------------------------------------------------------
# Sidecar writers
# ---------------------------------------------------------------------------


def _write_run_events(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    lines: list[dict[str, object]],
) -> Path:
    path = _sidecar_path(workspace_root, agent_id, skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, sort_keys=True) + "\n")
    return path


def _loaded_event(
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    run_id: str = "run_001",
    tenant_id: str = "default",
    loaded_at: str | None = None,
) -> dict[str, object]:
    ts = loaded_at or _NOW.isoformat()
    return {
        "action": "agent.skill.loaded",
        "agent_id": agent_id,
        "contributed_at": None,
        "loaded_at": ts,
        "run_id": run_id,
        "skill_id": skill_id,
        "tenant_id": tenant_id,
    }


def _contributed_event(
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    run_id: str = "run_001",
    tenant_id: str = "default",
    outcome: str = "success",
    contributed_at: str | None = None,
) -> dict[str, object]:
    ts = contributed_at or _NOW.isoformat()
    return {
        "action": "agent.skill.contributed",
        "agent_id": agent_id,
        "contributed_at": ts,
        "loaded_at": None,
        "outcome": outcome,
        "run_id": run_id,
        "skill_id": skill_id,
        "tenant_id": tenant_id,
    }


def _write_ratings_file(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    lines: list[dict[str, object]],
) -> Path:
    path = _operator_ratings_path(workspace_root, agent_id, skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, sort_keys=True) + "\n")
    return path


def _rating_record(
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    tenant_id: str = "default",
    rating: str = "useful",
    rated_by: str = "operator-1",
    rated_at: str | None = None,
) -> dict[str, object]:
    ts = rated_at or _NOW.replace(microsecond=next(_TS_COUNTER)).isoformat()
    return {
        "action": "agent.skill.operator_rated",
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "rating": rating,
        "rated_by": rated_by,
        "rated_at": ts,
    }


# ---------------------------------------------------------------------------
# Empty / insufficient data
# ---------------------------------------------------------------------------


def test_g1_empty_all_axes_returns_insufficient_data(tmp_path: Path) -> None:
    """No data for any axis → global_score=None, confidence=0.0, reason set."""
    al = _audit_log(tmp_path)
    result = compute_effectiveness_score(
        skill_id="sk_nonexistent",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert result.global_score is None
    assert result.confidence == 0.0
    assert result.reason == EffectivenessReason.INSUFFICIENT_DATA
    assert result.axes_breakdown is None


# ---------------------------------------------------------------------------
# All axes maximum (full confidence for all three)
# ---------------------------------------------------------------------------


def test_g1_all_axes_maximum_score_one(tmp_path: Path) -> None:
    """All axes at max score + full confidence → composite=1.0, confidence=1.0."""
    al = _audit_log(tmp_path)
    # Adoption: 10 loads → confidence=1.0, score=1.0
    _write_run_events(
        tmp_path,
        "test-agent",
        "sk_max",
        [_loaded_event(skill_id="sk_max", run_id=f"r{i}") for i in range(10)],
    )
    # Outcome: 10 successes → correlation_score=1.0, confidence=1.0
    _write_run_events(
        tmp_path,
        "test-agent",
        "sk_max",
        [
            _contributed_event(skill_id="sk_max", run_id=f"r{i}", outcome="success")
            for i in range(10)
        ],
    )
    # Feedback: 5 useful → feedback_score=1.0, confidence=1.0
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_max",
        [_rating_record(skill_id="sk_max", rating="useful") for _ in range(5)],
    )

    result = compute_effectiveness_score(
        skill_id="sk_max",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert result.global_score == pytest.approx(1.0)
    assert result.confidence == pytest.approx(1.0)
    assert result.reason is None
    assert result.axes_breakdown is not None
    assert result.axes_breakdown.adoption.score == 1.0
    assert result.axes_breakdown.adoption.confidence == 1.0
    assert result.axes_breakdown.outcome.score == 1.0
    assert result.axes_breakdown.outcome.confidence == 1.0
    assert result.axes_breakdown.feedback.score == 1.0
    assert result.axes_breakdown.feedback.confidence == 1.0


# ---------------------------------------------------------------------------
# Varied scores, full confidence — weighted formula verification
# ---------------------------------------------------------------------------


def test_g1_varied_scores_weighted_formula(tmp_path: Path) -> None:
    """Verify Q9 weighted formula with varied axis scores at full confidence."""
    al = _audit_log(tmp_path)
    # Adoption: score=1.0, confidence=1.0
    _write_run_events(
        tmp_path,
        "test-agent",
        "sk_var",
        [_loaded_event(skill_id="sk_var", run_id=f"r{i}") for i in range(10)],
    )
    # Outcome: 5 success + 5 failure → score=0.5, confidence=1.0
    for i in range(5):
        _write_run_events(
            tmp_path,
            "test-agent",
            "sk_var",
            [_contributed_event(skill_id="sk_var", run_id=f"s{i}", outcome="success")],
        )
    for i in range(5):
        _write_run_events(
            tmp_path,
            "test-agent",
            "sk_var",
            [_contributed_event(skill_id="sk_var", run_id=f"f{i}", outcome="failure")],
        )
    # Feedback: 2 useful + 1 harmful + 2 neutral → raw=(2-1)/5=0.2 → score=0.6, conf=1.0
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_var",
        [
            _rating_record(skill_id="sk_var", rating="useful"),
            _rating_record(skill_id="sk_var", rating="useful"),
            _rating_record(skill_id="sk_var", rating="harmful"),
            _rating_record(skill_id="sk_var", rating="neutral"),
            _rating_record(skill_id="sk_var", rating="neutral"),
        ],
    )

    result = compute_effectiveness_score(
        skill_id="sk_var",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    # numerator = 0.25*1.0*1.0 + 0.35*0.5*1.0 + 0.40*0.6*1.0 = 0.25+0.175+0.24 = 0.665
    # denominator = 1.0
    assert result.global_score == pytest.approx(0.665, abs=0.001)
    assert result.confidence == 1.0
    assert result.axes_breakdown is not None
    assert result.axes_breakdown.outcome.score == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Mixed confidence — feedback axis has zero confidence, drops out
# ---------------------------------------------------------------------------


def test_g1_mixed_confidence_feedback_zero(tmp_path: Path) -> None:
    """Feedback axis at zero confidence drops out of composite entirely."""
    al = _audit_log(tmp_path)
    # Adoption: 10 loads → confidence=1.0, score=1.0
    _write_run_events(
        tmp_path,
        "test-agent",
        "sk_mix",
        [_loaded_event(skill_id="sk_mix", run_id=f"r{i}") for i in range(10)],
    )
    # Outcome: 3 success + 2 failure → score=0.6, confidence=0.5
    events: list[dict[str, object]] = []
    for i in range(3):
        events.append(_contributed_event(skill_id="sk_mix", run_id=f"s{i}", outcome="success"))
    for i in range(2):
        events.append(_contributed_event(skill_id="sk_mix", run_id=f"f{i}", outcome="failure"))
    _write_run_events(tmp_path, "test-agent", "sk_mix", events)
    # Feedback: no ratings → confidence=0.0, score=None

    result = compute_effectiveness_score(
        skill_id="sk_mix",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    # numerator = 0.25*1.0*1.0 + 0.35*0.6*0.5 + 0.40*0*0 = 0.25 + 0.105 = 0.355
    # denominator = 0.25*1.0 + 0.35*0.5 + 0.40*0 = 0.25 + 0.175 = 0.425
    assert result.global_score == pytest.approx(0.355 / 0.425, abs=0.001)
    assert result.confidence == pytest.approx(0.425, abs=0.001)
    assert result.axes_breakdown is not None
    assert result.axes_breakdown.feedback.score == 0.0
    assert result.axes_breakdown.feedback.confidence == 0.0


# ---------------------------------------------------------------------------
# One axis only — others zero, composite = that axis score
# ---------------------------------------------------------------------------


def test_g1_adoption_only_score_one(tmp_path: Path) -> None:
    """Only adoption has data → composite = adoption score, confidence = weighted adoption conf."""
    al = _audit_log(tmp_path)
    _write_run_events(
        tmp_path,
        "test-agent",
        "sk_adopt",
        [_loaded_event(skill_id="sk_adopt", run_id=f"r{i}") for i in range(10)],
    )
    result = compute_effectiveness_score(
        skill_id="sk_adopt",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert result.global_score == 1.0
    assert result.confidence == pytest.approx(0.25)  # only adoption weight
    assert result.axes_breakdown is not None
    assert result.axes_breakdown.adoption.score == 1.0
    assert result.axes_breakdown.adoption.confidence == 1.0
    assert result.axes_breakdown.outcome.confidence == 0.0
    assert result.axes_breakdown.feedback.confidence == 0.0


def test_g1_outcome_only(tmp_path: Path) -> None:
    """Only outcome has data → composite = outcome score."""
    al = _audit_log(tmp_path)
    _write_run_events(
        tmp_path,
        "test-agent",
        "sk_out",
        [
            _contributed_event(skill_id="sk_out", run_id=f"r{i}", outcome="success")
            for i in range(10)
        ],
    )
    result = compute_effectiveness_score(
        skill_id="sk_out",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert result.global_score == 1.0
    assert result.confidence == pytest.approx(0.35)  # only outcome weight


def test_g1_feedback_only(tmp_path: Path) -> None:
    """Only feedback has data → composite = feedback score."""
    al = _audit_log(tmp_path)
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_fb",
        [_rating_record(skill_id="sk_fb", rating="harmful") for _ in range(5)],
    )
    result = compute_effectiveness_score(
        skill_id="sk_fb",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    # All harmful → feedback_score=0.0, confidence=1.0
    assert result.global_score == 0.0
    assert result.confidence == pytest.approx(0.40)  # only feedback weight


# ---------------------------------------------------------------------------
# Tenant scoping
# ---------------------------------------------------------------------------


def test_g1_tenant_scoping(tmp_path: Path) -> None:
    """Tenant filter scopes all three axes correctly."""
    al = _audit_log(tmp_path)
    # Write data for "acme" tenant.
    _write_run_events(
        tmp_path,
        "test-agent",
        "sk_tenant",
        [
            _loaded_event(skill_id="sk_tenant", run_id="r1", tenant_id="acme"),
            _loaded_event(skill_id="sk_tenant", run_id="r2", tenant_id="acme"),
        ],
    )
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_tenant",
        [_rating_record(skill_id="sk_tenant", rating="useful", tenant_id="acme")],
    )
    result = compute_effectiveness_score(
        skill_id="sk_tenant",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
        tenant_id="acme",
    )
    assert result.tenant_id == "acme"
    assert result.axes_breakdown is not None
    # Adoption: 2 loads → confidence=0.2
    assert result.axes_breakdown.adoption.confidence == 0.2


# ---------------------------------------------------------------------------
# Partial adoption confidence
# ---------------------------------------------------------------------------


def test_g1_partial_adoption_confidence(tmp_path: Path) -> None:
    """Adoption with partial confidence + outcome with partial → weighted composite."""
    al = _audit_log(tmp_path)
    # 3 loads → confidence=0.3
    _write_run_events(
        tmp_path,
        "test-agent",
        "sk_partial",
        [_loaded_event(skill_id="sk_partial", run_id=f"r{i}") for i in range(3)],
    )
    # 5 successes → score=1.0, confidence=0.5
    _write_run_events(
        tmp_path,
        "test-agent",
        "sk_partial",
        [
            _contributed_event(skill_id="sk_partial", run_id=f"s{i}", outcome="success")
            for i in range(5)
        ],
    )
    result = compute_effectiveness_score(
        skill_id="sk_partial",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    # numerator = 0.25*1.0*0.3 + 0.35*1.0*0.5 = 0.075 + 0.175 = 0.25
    # denominator = 0.25*0.3 + 0.35*0.5 = 0.075 + 0.175 = 0.25
    # composite = 1.0, confidence = 0.25
    assert result.global_score == pytest.approx(1.0)
    assert result.confidence == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# computed_at timestamp
# ---------------------------------------------------------------------------


def test_g1_computed_at_is_set(tmp_path: Path) -> None:
    """EffectivenessScore carries a computed_at UTC timestamp."""
    al = _audit_log(tmp_path)
    result = compute_effectiveness_score(
        skill_id="sk_ts",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert result.computed_at is not None
    assert result.computed_at.tzinfo == UTC


# ---------------------------------------------------------------------------
# CF #2 — axis computation failure
# ---------------------------------------------------------------------------


def test_g1_cf2_axis_error_emits_and_raises(tmp_path: Path, mocker) -> None:
    """Forced axis error → effectiveness_error_during_aggregation emitted + re-raised."""
    al = _audit_log(tmp_path)
    # Force compute_adoption_metrics to raise.
    mocker.patch(
        "meta_harness.skill_effectiveness.compute_adoption_metrics",
        side_effect=RuntimeError("simulated axis failure"),
    )
    with pytest.raises(RuntimeError, match="simulated axis failure"):
        compute_effectiveness_score(
            skill_id="sk_cf2",
            agent_id="test-agent",
            audit_log=al,
            workspace_root=tmp_path,
        )
    audit_text = al.path.read_text(encoding="utf-8")
    assert "meta_harness.skill.effectiveness_error" in audit_text
    assert "effectiveness_error_during_aggregation" in audit_text
    assert "sk_cf2" in audit_text
