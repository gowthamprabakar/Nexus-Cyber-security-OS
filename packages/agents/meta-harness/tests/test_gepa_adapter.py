"""Tests — ``meta_harness.gepa_adapter`` (v0.2.5 Task 4).

Verifies the three brainstorm Q5 policy decisions in adapter form:
(a) SKIP None / zero-confidence, (b) MODULATE by score x confidence,
(c) USE operator notes (cached at construction). Plus CF #2 graceful
degradation, tenant scoping, and DSPy Example shape compatibility.

No real GEPA compilation runs (Task 5+); the metric is exercised directly.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from charter.audit import AuditLog
from meta_harness import gepa_adapter as gepa_adapter_module
from meta_harness.gepa_adapter import GEPAMetricAdapter
from meta_harness.schemas import (
    AxisBreakdown,
    EffectivenessAxes,
    EffectivenessReason,
    EffectivenessScore,
)


def _audit(workspace_root: Path) -> AuditLog:
    return AuditLog(workspace_root / "audit.jsonl", agent="meta_harness", run_id="compile-cycle")


def _example(skill_id: str) -> SimpleNamespace:
    return SimpleNamespace(skill_id=skill_id)


def _write_effectiveness_sidecar(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    *,
    global_score: float | None,
    confidence: float,
    tenant_id: str = "default",
    reason: str | None = None,
) -> None:
    path = (
        workspace_root / ".nexus" / "deployed-skills" / agent_id / skill_id / "effectiveness.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    axes = (
        {
            "adoption": {"score": 0.90, "confidence": 0.88},
            "outcome": {"score": 0.85, "confidence": 0.90},
            "feedback": {"score": 0.87, "confidence": 0.85},
        }
        if confidence > 0.0
        else None
    )
    if confidence == 0.0 and reason is None:
        reason = "insufficient_data"
    payload: dict[str, Any] = {
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "global_score": global_score,
        "confidence": confidence,
        "by_agent": {},
        "by_tenant": {},
        "axes_breakdown": axes,
        "reason": reason,
        "computed_at": "2026-06-01T12:00:00+00:00",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_ratings_sidecar(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    notes: list[str],
    *,
    tenant_id: str = "default",
) -> None:
    path = (
        workspace_root
        / ".nexus"
        / "deployed-skills"
        / agent_id
        / skill_id
        / "operator-ratings.jsonl"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for i, note in enumerate(notes):
            f.write(
                json.dumps(
                    {
                        "action": "agent.skill.operator_rated",
                        "skill_id": skill_id,
                        "agent_id": agent_id,
                        "tenant_id": tenant_id,
                        "rating": "useful",
                        "note": note,
                        "rated_by": f"operator-{i}",
                        "rated_at": f"2026-06-01T1{i}:00:00+00:00",
                    }
                )
                + "\n"
            )


def _score(
    *, global_score: float | None, confidence: float, reason: EffectivenessReason | None = None
) -> EffectivenessScore:
    axes = (
        EffectivenessAxes(
            adoption=AxisBreakdown(score=0.9, confidence=0.9),
            outcome=AxisBreakdown(score=0.8, confidence=0.9),
            feedback=AxisBreakdown(score=0.85, confidence=0.85),
        )
        if confidence > 0.0
        else None
    )
    return EffectivenessScore(
        skill_id="x/y",
        agent_id="investigation",
        tenant_id="default",
        global_score=global_score,
        confidence=confidence,
        axes_breakdown=axes,
        reason=reason,
        computed_at=datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_init_various_agent_ids(tmp_path: Path) -> None:
    for agent_id in ("investigation", "cloud_posture", "remediation"):
        adapter = GEPAMetricAdapter(agent_id, workspace_root=tmp_path, audit_log=_audit(tmp_path))
        assert adapter.cached_skill_ids == ()


# ---------------------------------------------------------------------------
# Q5-a — SKIP
# ---------------------------------------------------------------------------


def test_returns_none_when_score_absent(tmp_path: Path) -> None:
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert adapter(_example("iam/role-chain")) is None


def test_returns_none_when_zero_confidence(tmp_path: Path) -> None:
    _write_effectiveness_sidecar(
        tmp_path, "investigation", "iam/unproven", global_score=None, confidence=0.0
    )
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert adapter(_example("iam/unproven")) is None


# ---------------------------------------------------------------------------
# Q5-b — MODULATE
# ---------------------------------------------------------------------------


def test_returns_score_with_feedback_for_valid_score(tmp_path: Path) -> None:
    """Q5-c: GEPA metric returns ScoreWithFeedback (score + feedback), NOT a raw
    tuple (which crashes DSPy's evaluator)."""
    _write_effectiveness_sidecar(
        tmp_path, "investigation", "iam/role-chain", global_score=0.8, confidence=0.5
    )
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    result = adapter(_example("iam/role-chain"))
    assert result is not None
    assert isinstance(result.score, float)
    assert isinstance(result.feedback, str)
    # Must NOT be a bare tuple (the Q5-c crash shape).
    assert not isinstance(result, tuple)


def test_modulation_is_score_times_confidence(tmp_path: Path) -> None:
    _write_effectiveness_sidecar(
        tmp_path, "investigation", "iam/role-chain", global_score=0.8, confidence=0.5
    )
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    scalar = adapter(_example("iam/role-chain")).score
    assert scalar == pytest.approx(0.8 * 0.5)


# ---------------------------------------------------------------------------
# Q5-c — reflection (reason + axes + operator notes)
# ---------------------------------------------------------------------------


def test_reflection_includes_axes_breakdown(tmp_path: Path) -> None:
    _write_effectiveness_sidecar(
        tmp_path, "investigation", "iam/role-chain", global_score=0.8, confidence=0.5
    )
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    reflection = adapter(_example("iam/role-chain")).feedback
    assert "axes:" in reflection
    assert "adoption=" in reflection and "outcome=" in reflection and "feedback=" in reflection


def test_reflection_includes_reason_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """reason is normally None for non-zero-confidence scores; verify the
    reflection surfaces it when set, via a constructed score."""
    monkeypatch.setattr(
        gepa_adapter_module,
        "get_effectiveness_score",
        lambda *a, **k: _score(
            global_score=0.7,
            confidence=0.6,
            reason=EffectivenessReason.OPERATOR_MARKED_ARCHIVED,
        ),
    )
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    reflection = adapter(_example("iam/x")).feedback
    assert "reason=operator_marked_archived" in reflection


def test_reflection_includes_operator_note(tmp_path: Path) -> None:
    _write_effectiveness_sidecar(
        tmp_path, "investigation", "iam/role-chain", global_score=0.8, confidence=0.5
    )
    _write_ratings_sidecar(
        tmp_path, "investigation", "iam/role-chain", ["sharpened the role-chain head heuristic"]
    )
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    reflection = adapter(_example("iam/role-chain")).feedback
    assert "operator: sharpened the role-chain head heuristic" in reflection


# ---------------------------------------------------------------------------
# Cache lifecycle (Q5-c: primed at construction, not per call)
# ---------------------------------------------------------------------------


def test_operator_notes_primed_at_construction_not_per_call(tmp_path: Path) -> None:
    _write_effectiveness_sidecar(
        tmp_path, "investigation", "iam/role-chain", global_score=0.8, confidence=0.5
    )
    _write_ratings_sidecar(tmp_path, "investigation", "iam/role-chain", ["cached note"])
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert adapter.cached_skill_ids == ("iam/role-chain",)

    # Delete the ratings sidecar AFTER construction — a per-call read would
    # now miss the note; a construction-time cache still has it.
    (
        tmp_path
        / ".nexus"
        / "deployed-skills"
        / "investigation"
        / "iam/role-chain"
        / "operator-ratings.jsonl"
    ).unlink()
    reflection = adapter(_example("iam/role-chain")).feedback
    assert "operator: cached note" in reflection


def test_cached_skill_ids_introspection(tmp_path: Path) -> None:
    _write_ratings_sidecar(tmp_path, "investigation", "beta/two", ["n2"])
    _write_ratings_sidecar(tmp_path, "investigation", "alpha/one", ["n1"])
    _write_ratings_sidecar(tmp_path, "investigation", "gamma/three", [])  # no notes → absent
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert adapter.cached_skill_ids == ("alpha/one", "beta/two")


# ---------------------------------------------------------------------------
# CF #2 graceful degradation
# ---------------------------------------------------------------------------


def test_cf2_read_failure_emits_error_and_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("simulated G1 sidecar read failure")

    monkeypatch.setattr(gepa_adapter_module, "get_effectiveness_score", _boom)
    audit_log = _audit(tmp_path)
    adapter = GEPAMetricAdapter("investigation", workspace_root=tmp_path, audit_log=audit_log)
    assert adapter(_example("iam/explodes")) is None

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "meta_harness.skill.effectiveness_error" in audit_text
    assert "effectiveness_read_failed" in audit_text
    assert "iam/explodes" in audit_text


# ---------------------------------------------------------------------------
# Tenant scoping
# ---------------------------------------------------------------------------


def test_tenant_scoping_preserved(tmp_path: Path) -> None:
    _write_effectiveness_sidecar(
        tmp_path, "investigation", "iam/scoped", global_score=0.8, confidence=0.5, tenant_id="acme"
    )
    # Default tenant → no score visible → skip.
    default_adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert default_adapter(_example("iam/scoped")) is None
    # Matching tenant → scored.
    acme_adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path), tenant_id="acme"
    )
    result = acme_adapter(_example("iam/scoped"))
    assert result is not None
    assert result.score == pytest.approx(0.4)


# ---------------------------------------------------------------------------
# Contract / DSPy compatibility
# ---------------------------------------------------------------------------


def test_missing_skill_id_raises(tmp_path: Path) -> None:
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    with pytest.raises(ValueError, match="skill_id"):
        adapter(SimpleNamespace())


def test_dspy_example_shape_compatibility(tmp_path: Path) -> None:
    """The adapter works with a real ``dspy.Example`` carrying skill_id."""
    dspy = pytest.importorskip("dspy")
    _write_effectiveness_sidecar(
        tmp_path, "investigation", "iam/role-chain", global_score=0.6, confidence=0.5
    )
    adapter = GEPAMetricAdapter(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    example = dspy.Example(skill_id="iam/role-chain", task="follow the chain").with_inputs("task")
    result = adapter(example, dspy.Prediction(answer="..."))
    assert result is not None
    assert result.score == pytest.approx(0.3)
