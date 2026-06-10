"""D.3 v0.2 Task 15 — Investigation-agent handoff tests (Q6, no auto-escalation)."""

from __future__ import annotations

from runtime_threat.handoff import (
    INVESTIGATION_KEY,
    SNAPSHOT_REF_KEY,
    attach_investigation_handoff,
    should_recommend_investigation,
)


def test_critical_recommends() -> None:
    assert should_recommend_investigation(severity="critical") is True


def test_high_recommends() -> None:
    assert should_recommend_investigation(severity="High") is True  # case-insensitive


def test_medium_does_not_recommend_alone() -> None:
    assert should_recommend_investigation(severity="medium") is False


def test_cross_sensor_recommends() -> None:
    assert should_recommend_investigation(severity="medium", cross_sensor=True) is True


def test_high_confidence_recommends() -> None:
    assert should_recommend_investigation(severity="low", max_confidence=0.9) is True
    assert should_recommend_investigation(severity="low", max_confidence=0.5) is False


def test_attach_sets_flag() -> None:
    out = attach_investigation_handoff({"process": "bash"}, recommended=True)
    assert out[INVESTIGATION_KEY] is True and out["process"] == "bash"


def test_attach_includes_snapshot_ref() -> None:
    out = attach_investigation_handoff({}, recommended=True, snapshot_ref="snap1")
    assert out[SNAPSHOT_REF_KEY] == "snap1"


def test_attach_without_snapshot_ref() -> None:
    out = attach_investigation_handoff({}, recommended=False)
    assert out[INVESTIGATION_KEY] is False and SNAPSHOT_REF_KEY not in out


def test_attach_does_not_mutate_input() -> None:
    ev: dict[str, object] = {}
    attach_investigation_handoff(ev, recommended=True)
    assert ev == {}


def test_no_auto_escalation_surface() -> None:
    # Q6: D.3 emits the flag only — no escalate/notify function exists.
    import runtime_threat.handoff as mod

    assert not hasattr(mod, "escalate")
    assert not hasattr(mod, "notify_investigation")
