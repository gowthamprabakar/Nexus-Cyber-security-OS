"""G1 backwards-compat handler tests — Task 10.

10 tests covering detect_agent_emission_status and
apply_backwards_compat_reason.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from charter.audit import AuditLog
from meta_harness.effectiveness_compat import (
    AgentEmissionStatus,
    apply_backwards_compat_reason,
    detect_agent_emission_status,
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


def _make_score(
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    tenant_id: str = "default",
    global_score: float | None = None,
    confidence: float = 0.0,
    reason: EffectivenessReason = EffectivenessReason.INSUFFICIENT_DATA,
) -> EffectivenessScore:
    """Create a zero-confidence score (typical for backwards-compat path)."""
    return EffectivenessScore(
        skill_id=skill_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        global_score=global_score,
        confidence=confidence,
        axes_breakdown=None,
        reason=reason,
        computed_at=_NOW,
    )


def _make_score_with_confidence(
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    global_score: float = 0.5,
    confidence: float = 0.3,
) -> EffectivenessScore:
    axes = EffectivenessAxes(
        adoption=AxisBreakdown(score=global_score, confidence=confidence),
        outcome=AxisBreakdown(score=global_score, confidence=confidence),
        feedback=AxisBreakdown(score=global_score, confidence=confidence),
    )
    return EffectivenessScore(
        skill_id=skill_id,
        agent_id=agent_id,
        global_score=global_score,
        confidence=confidence,
        axes_breakdown=axes,
        reason=None,
        computed_at=_NOW,
    )


def _write_sidecar_event(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    *,
    action: str = "agent.skill.loaded",
    tenant_id: str = "default",
) -> Path:
    path = workspace_root / ".nexus" / "deployed-skills" / agent_id / skill_id / "run-events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "action": action,
        "agent_id": agent_id,
        "skill_id": skill_id,
        "tenant_id": tenant_id,
        "run_id": "run_001",
        "loaded_at": _NOW.isoformat(),
        "contributed_at": None,
    }
    path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _append_audit_chain_event(
    audit_log: AuditLog,
    *,
    action: str = "agent.skill.loaded",
    agent_id: str = "test-agent",
    skill_id: str = "sk_test",
    tenant_id: str = "default",
) -> None:
    payload = {
        "agent_id": agent_id,
        "skill_id": skill_id,
        "tenant_id": tenant_id,
        "run_id": "run_001",
        "loaded_at": _NOW.isoformat(),
        "contributed_at": None,
    }
    audit_log.append(action, payload)


# ---------------------------------------------------------------------------
# detect_agent_emission_status
# ---------------------------------------------------------------------------


def test_g1_no_events_anywhere_returns_silent(tmp_path: Path) -> None:
    """No sidecar, no audit chain → AgentEmissionStatus.SILENT."""
    al = _audit_log(tmp_path)
    status = detect_agent_emission_status(
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert status == AgentEmissionStatus.SILENT


def test_g1_sidecar_loaded_event_returns_emitting(tmp_path: Path) -> None:
    """A loaded event in the sidecar → AgentEmissionStatus.EMITTING."""
    al = _audit_log(tmp_path)
    _write_sidecar_event(tmp_path, "test-agent", "sk_emit", action="agent.skill.loaded")
    status = detect_agent_emission_status(
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert status == AgentEmissionStatus.EMITTING


def test_g1_sidecar_contributed_event_returns_emitting(tmp_path: Path) -> None:
    """A contributed event in the sidecar → AgentEmissionStatus.EMITTING."""
    al = _audit_log(tmp_path)
    _write_sidecar_event(tmp_path, "test-agent", "sk_emit", action="agent.skill.contributed")
    status = detect_agent_emission_status(
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert status == AgentEmissionStatus.EMITTING


def test_g1_audit_chain_no_sidecar_returns_unknown(tmp_path: Path) -> None:
    """Events in audit chain but no sidecar projection → UNKNOWN."""
    al = _audit_log(tmp_path)
    _append_audit_chain_event(al, action="agent.skill.loaded", skill_id="sk_unk")
    status = detect_agent_emission_status(
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert status == AgentEmissionStatus.UNKNOWN


# ---------------------------------------------------------------------------
# apply_backwards_compat_reason
# ---------------------------------------------------------------------------


def test_g1_silent_agent_zero_confidence_sets_reason(tmp_path: Path) -> None:
    """Silent agent + zero-confidence → reason = agent_not_emitting_events."""
    al = _audit_log(tmp_path)
    score = _make_score(skill_id="sk_silent", confidence=0.0)
    result = apply_backwards_compat_reason(
        score, "test-agent", audit_log=al, workspace_root=tmp_path
    )
    assert result.reason == EffectivenessReason.AGENT_NOT_EMITTING_EVENTS
    assert result.confidence == 0.0
    assert result.global_score is None


def test_g1_emitting_agent_preserves_insufficient_data(tmp_path: Path) -> None:
    """Emitting agent + zero-confidence → reason stays insufficient_data."""
    al = _audit_log(tmp_path)
    _write_sidecar_event(tmp_path, "test-agent", "sk_emitting", action="agent.skill.loaded")
    score = _make_score(skill_id="sk_emitting", confidence=0.0)
    result = apply_backwards_compat_reason(
        score, "test-agent", audit_log=al, workspace_root=tmp_path
    )
    assert result.reason == EffectivenessReason.INSUFFICIENT_DATA


def test_g1_nonzero_confidence_returned_unchanged(tmp_path: Path) -> None:
    """Score with confidence > 0 is returned unchanged regardless of agent status."""
    al = _audit_log(tmp_path)
    score = _make_score_with_confidence(global_score=0.7, confidence=0.5)
    result = apply_backwards_compat_reason(
        score, "test-agent", audit_log=al, workspace_root=tmp_path
    )
    assert result.global_score == 0.7
    assert result.confidence == 0.5
    assert result.reason is None


def test_g1_non_insufficient_data_reason_preserved(tmp_path: Path) -> None:
    """Score with a reason other than insufficient_data is returned unchanged."""
    al = _audit_log(tmp_path)
    _write_sidecar_event(tmp_path, "test-agent", "sk_arch", action="agent.skill.loaded")
    score = _make_score(
        skill_id="sk_arch",
        confidence=0.0,
        reason=EffectivenessReason.OPERATOR_MARKED_ARCHIVED,
    )
    result = apply_backwards_compat_reason(
        score, "test-agent", audit_log=al, workspace_root=tmp_path
    )
    assert result.reason == EffectivenessReason.OPERATOR_MARKED_ARCHIVED


# ---------------------------------------------------------------------------
# CF #2 — detection failure
# ---------------------------------------------------------------------------


def test_g1_cf2_detection_failure_emits_error(tmp_path: Path, mocker) -> None:
    """Forced failure in detect_agent_emission_status → error emitted + raised."""
    al = _audit_log(tmp_path)
    mocker.patch(
        "meta_harness.effectiveness_compat._agent_has_sidecar_events",
        side_effect=RuntimeError("simulated scan failure"),
    )
    with pytest.raises(RuntimeError, match="simulated scan failure"):
        detect_agent_emission_status(
            agent_id="test-agent",
            audit_log=al,
            workspace_root=tmp_path,
        )
    audit_text = al.path.read_text(encoding="utf-8")
    assert "meta_harness.skill.effectiveness_error" in audit_text
    assert "emission_status_detection_failure" in audit_text


# ---------------------------------------------------------------------------
# Tenant scoping
# ---------------------------------------------------------------------------


def test_g1_tenant_scoping_does_not_affect_detection(tmp_path: Path) -> None:
    """Emission detection is tenant-agnostic — any tenant's events count."""
    al = _audit_log(tmp_path)
    # Write an event for tenant "acme".
    _write_sidecar_event(tmp_path, "test-agent", "sk_tenant", tenant_id="acme")
    # Emission detection doesn't filter by tenant — any event counts.
    status = detect_agent_emission_status(
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert status == AgentEmissionStatus.EMITTING
