"""Tests — `meta_harness.skill_deprecation` (Hermes Phase 5 dual-trigger + sunset).

Pins the dual-trigger logic (time OR performance), the sunset → expired transition, flag-clear
on recovery, and the advisory controller's state persistence (age from first-observation).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from meta_harness.skill_deprecation import (
    DEFAULT_MAX_AGE_DAYS,
    DEFAULT_MIN_EFFECTIVENESS,
    DEFAULT_SUNSET_DAYS,
    DeprecationPhase,
    DeprecationTrigger,
    SkillDeprecationController,
    evaluate_skill_deprecation,
)

_NOW = datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC)


def _seed_skill(
    workspace: Path,
    agent_id: str,
    skill_id: str,
    *,
    global_score: float | None = None,
    confidence: float = 0.0,
) -> None:
    skill_dir = workspace / ".nexus" / "deployed-skills" / agent_id / skill_id
    skill_dir.mkdir(parents=True, exist_ok=True)
    if global_score is None and confidence == 0.0:
        return
    axes = (
        {
            "adoption": {"score": 0.9, "confidence": 0.9},
            "outcome": {"score": 0.8, "confidence": 0.9},
            "feedback": {"score": 0.85, "confidence": 0.9},
        }
        if confidence > 0.0
        else None
    )
    (skill_dir / "effectiveness.json").write_text(
        json.dumps(
            {
                "skill_id": skill_id,
                "agent_id": agent_id,
                "tenant_id": "default",
                "global_score": global_score,
                "confidence": confidence,
                "by_agent": {},
                "by_tenant": {},
                "axes_breakdown": axes,
                "reason": None,
                "computed_at": "2026-06-01T12:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )


# --------------------------------------------------------------- pure dual-trigger evaluation


def _eval(**kw: object) -> object:
    base = {
        "agent_id": "investigation",
        "skill_id": "s1",
        "age_days": 0.0,
        "effectiveness": 0.9,
        "confidence": 0.9,
        "flagged_at": None,
        "now": _NOW,
    }
    base.update(kw)
    return evaluate_skill_deprecation(**base)  # type: ignore[arg-type]


def test_no_trigger_is_active() -> None:
    d = _eval()
    assert d.phase is DeprecationPhase.ACTIVE  # type: ignore[attr-defined]
    assert d.triggers == ()  # type: ignore[attr-defined]
    assert d.flagged_at is None  # type: ignore[attr-defined]


def test_stale_age_triggers_sunset() -> None:
    d = _eval(age_days=float(DEFAULT_MAX_AGE_DAYS + 1))
    assert DeprecationTrigger.STALE_AGE in d.triggers  # type: ignore[attr-defined]
    assert d.phase is DeprecationPhase.SUNSET  # type: ignore[attr-defined]
    assert d.flagged_at == _NOW  # type: ignore[attr-defined]


def test_low_effectiveness_triggers_sunset() -> None:
    d = _eval(effectiveness=DEFAULT_MIN_EFFECTIVENESS - 0.1, confidence=0.9)
    assert DeprecationTrigger.LOW_EFFECTIVENESS in d.triggers  # type: ignore[attr-defined]
    assert d.phase is DeprecationPhase.SUNSET  # type: ignore[attr-defined]


def test_unscored_skill_never_deprecated_on_performance() -> None:
    # confidence == 0 → no performance signal → no LOW_EFFECTIVENESS trigger.
    d = _eval(effectiveness=None, confidence=0.0)
    assert d.phase is DeprecationPhase.ACTIVE  # type: ignore[attr-defined]


def test_sunset_elapsed_becomes_expired() -> None:
    flagged = _NOW - timedelta(days=DEFAULT_SUNSET_DAYS + 1)
    d = _eval(effectiveness=0.1, confidence=0.9, flagged_at=flagged)
    assert d.phase is DeprecationPhase.EXPIRED  # type: ignore[attr-defined]
    assert (
        d.flagged_at == flagged
    )  # clock keeps the original flag time  # type: ignore[attr-defined]


def test_within_sunset_window_stays_sunset() -> None:
    flagged = _NOW - timedelta(days=DEFAULT_SUNSET_DAYS - 1)
    d = _eval(effectiveness=0.1, confidence=0.9, flagged_at=flagged)
    assert d.phase is DeprecationPhase.SUNSET  # type: ignore[attr-defined]


def test_recovery_clears_flag() -> None:
    # Previously flagged, but effectiveness recovered + not stale → flag dropped.
    flagged = _NOW - timedelta(days=2)
    d = _eval(effectiveness=0.95, confidence=0.9, age_days=1.0, flagged_at=flagged)
    assert d.phase is DeprecationPhase.ACTIVE  # type: ignore[attr-defined]
    assert d.flagged_at is None  # type: ignore[attr-defined]


# --------------------------------------------------------------- controller (advisory + state)


def test_controller_flags_low_effectiveness_and_persists_state(tmp_path: Path) -> None:
    _seed_skill(tmp_path, "investigation", "bad", global_score=0.1, confidence=0.9)
    _seed_skill(tmp_path, "investigation", "good", global_score=0.95, confidence=0.9)
    controller = SkillDeprecationController(workspace_root=tmp_path)

    decisions = {d.skill_id: d for d in controller.evaluate_all(now=_NOW)}
    assert decisions["bad"].phase is DeprecationPhase.SUNSET
    assert decisions["good"].phase is DeprecationPhase.ACTIVE

    state = json.loads(
        (tmp_path / ".nexus" / "skill-deprecation" / "state.json").read_text(encoding="utf-8")
    )
    assert "flagged_at" in state["investigation:bad"]
    assert "flagged_at" not in state["investigation:good"]
    assert "first_observed_at" in state["investigation:good"]


def test_controller_age_anchored_to_first_observation(tmp_path: Path) -> None:
    _seed_skill(tmp_path, "investigation", "s1", global_score=0.95, confidence=0.9)
    controller = SkillDeprecationController(workspace_root=tmp_path)

    # First observation: healthy + brand-new → active.
    first = controller.evaluate_all(now=_NOW)
    assert first[0].phase is DeprecationPhase.ACTIVE

    # Far in the future, same healthy score → STALE_AGE fires off the recorded first-observation.
    later = _NOW + timedelta(days=DEFAULT_MAX_AGE_DAYS + 5)
    second = {d.skill_id: d for d in controller.evaluate_all(now=later)}
    assert DeprecationTrigger.STALE_AGE in second["s1"].triggers
    assert second["s1"].phase is DeprecationPhase.SUNSET


def test_controller_drops_state_for_undeployed_skills(tmp_path: Path) -> None:
    _seed_skill(tmp_path, "investigation", "gone", global_score=0.1, confidence=0.9)
    controller = SkillDeprecationController(workspace_root=tmp_path)
    controller.evaluate_all(now=_NOW)

    # Remove the skill directory, re-evaluate → its state entry is pruned.
    import shutil

    shutil.rmtree(tmp_path / ".nexus" / "deployed-skills" / "investigation" / "gone")
    controller.evaluate_all(now=_NOW)
    state = json.loads(
        (tmp_path / ".nexus" / "skill-deprecation" / "state.json").read_text(encoding="utf-8")
    )
    assert "investigation:gone" not in state
