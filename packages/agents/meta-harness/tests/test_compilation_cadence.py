"""Tests — Task 7a compilation cadence controller (offline; no compilation).

Covers the cadence decision branches + priority order, per-agent lock
semantics, state-sidecar persistence, and signal aggregation. No DSPy
compilation, no factory, no eval-gate — those are Task 7b.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from meta_harness.compilation_cadence import (
    CadenceState,
    CompilationCadenceController,
    CompilationTrigger,
)

_BASE = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def _seed_skill(
    workspace: Path,
    agent_id: str,
    skill_id: str,
    *,
    global_score: float | None = None,
    confidence: float = 0.0,
    tenant_id: str = "default",
) -> None:
    """Create a deployed-skill dir; write effectiveness.json only when scored."""
    skill_dir = workspace / ".nexus" / "deployed-skills" / agent_id / skill_id
    skill_dir.mkdir(parents=True, exist_ok=True)
    if global_score is None and confidence == 0.0:
        return  # unscored skill — directory only (counts, no effectiveness signal)
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
                "tenant_id": tenant_id,
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


def _controller(tmp_path: Path, **kwargs: object) -> CompilationCadenceController:
    return CompilationCadenceController(workspace_root=tmp_path, **kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- decisions


def test_effectiveness_drop_below_threshold_fires(tmp_path: Path) -> None:
    _seed_skill(tmp_path, "investigation", "s1", global_score=0.30, confidence=0.9)
    _seed_skill(tmp_path, "investigation", "s2", global_score=0.20, confidence=0.9)
    c = _controller(tmp_path)
    # Never compiled, but effectiveness-drop (priority 2) wins over cron (priority 4).
    d = c.evaluate("investigation", now=_BASE)
    assert d.should_compile is True
    assert d.trigger is CompilationTrigger.EFFECTIVENESS_DROP


def test_effectiveness_above_threshold_no_compile(tmp_path: Path) -> None:
    _seed_skill(tmp_path, "investigation", "s1", global_score=0.80, confidence=0.9)
    c = _controller(tmp_path)
    c.record_compilation("investigation", now=_BASE)  # recent compile → cron not due
    d = c.evaluate("investigation", now=_BASE + timedelta(days=1))
    assert d.should_compile is False
    assert d.trigger is None


def test_skill_threshold_fires(tmp_path: Path) -> None:
    c = _controller(tmp_path)
    c.record_compilation("investigation", now=_BASE)  # baseline count = 0, recent
    for i in range(10):  # 10 new unscored skills (avg effectiveness = None)
        _seed_skill(tmp_path, "investigation", f"s{i}")
    d = c.evaluate("investigation", now=_BASE + timedelta(days=1))
    assert d.should_compile is True
    assert d.trigger is CompilationTrigger.SKILL_THRESHOLD


def test_below_skill_threshold_no_compile(tmp_path: Path) -> None:
    c = _controller(tmp_path)
    c.record_compilation("investigation", now=_BASE)
    for i in range(3):  # < threshold
        _seed_skill(tmp_path, "investigation", f"s{i}")
    d = c.evaluate("investigation", now=_BASE + timedelta(days=1))
    assert d.should_compile is False


def test_manual_trigger_fires(tmp_path: Path) -> None:
    c = _controller(tmp_path)
    c.record_compilation("investigation", now=_BASE)  # otherwise-healthy state
    c.request_manual("investigation")
    d = c.evaluate("investigation", now=_BASE + timedelta(days=1))
    assert d.should_compile is True
    assert d.trigger is CompilationTrigger.MANUAL


def test_weekly_cron_elapsed_fires(tmp_path: Path) -> None:
    _seed_skill(tmp_path, "investigation", "s1", global_score=0.80, confidence=0.9)
    c = _controller(tmp_path)
    c.record_compilation("investigation", now=_BASE)
    d = c.evaluate("investigation", now=_BASE + timedelta(days=8))
    assert d.should_compile is True
    assert d.trigger is CompilationTrigger.WEEKLY_CRON


def test_weekly_cron_not_elapsed_no_compile(tmp_path: Path) -> None:
    _seed_skill(tmp_path, "investigation", "s1", global_score=0.80, confidence=0.9)
    c = _controller(tmp_path)
    c.record_compilation("investigation", now=_BASE)
    d = c.evaluate("investigation", now=_BASE + timedelta(days=3))
    assert d.should_compile is False


def test_never_compiled_fires_initial_cron(tmp_path: Path) -> None:
    c = _controller(tmp_path)  # no skills, no state
    d = c.evaluate("investigation", now=_BASE)
    assert d.should_compile is True
    assert d.trigger is CompilationTrigger.WEEKLY_CRON
    assert "never compiled" in d.reason


def test_manual_beats_effectiveness_drop_priority(tmp_path: Path) -> None:
    """Priority order: MANUAL outranks EFFECTIVENESS_DROP."""
    _seed_skill(tmp_path, "investigation", "s1", global_score=0.10, confidence=0.9)
    c = _controller(tmp_path)
    c.request_manual("investigation")
    d = c.evaluate("investigation", now=_BASE)
    assert d.trigger is CompilationTrigger.MANUAL  # not EFFECTIVENESS_DROP


# --------------------------------------------------------------------------- signals


def test_average_effectiveness_skips_unscored(tmp_path: Path) -> None:
    _seed_skill(tmp_path, "investigation", "scored", global_score=0.60, confidence=0.9)
    _seed_skill(tmp_path, "investigation", "zeroconf", global_score=0.10, confidence=0.0)
    _seed_skill(tmp_path, "investigation", "unscored")
    c = _controller(tmp_path)
    assert c.average_effectiveness("investigation") == pytest.approx(0.60)


def test_average_effectiveness_none_when_no_scores(tmp_path: Path) -> None:
    _seed_skill(tmp_path, "investigation", "unscored")
    c = _controller(tmp_path)
    assert c.average_effectiveness("investigation") is None


def test_current_skill_count(tmp_path: Path) -> None:
    for i in range(4):
        _seed_skill(tmp_path, "investigation", f"s{i}")
    _seed_skill(tmp_path, "remediation", "other")  # different agent — not counted
    c = _controller(tmp_path)
    assert c.current_skill_count("investigation") == 4


# --------------------------------------------------------------------------- state


def test_record_compilation_persists_state(tmp_path: Path) -> None:
    for i in range(2):
        _seed_skill(tmp_path, "investigation", f"s{i}")
    c = _controller(tmp_path)
    c.record_compilation("investigation", now=_BASE)
    state = c.load_state("investigation")
    assert state.last_compile_at == _BASE
    assert state.skill_count_at_last_compile == 2
    assert state.manual_trigger_pending is False


def test_record_compilation_clears_manual_flag(tmp_path: Path) -> None:
    c = _controller(tmp_path)
    c.request_manual("investigation")
    assert c.load_state("investigation").manual_trigger_pending is True
    c.record_compilation("investigation", now=_BASE)
    assert c.load_state("investigation").manual_trigger_pending is False


def test_load_state_defaults_when_absent(tmp_path: Path) -> None:
    c = _controller(tmp_path)
    state = c.load_state("never-seen")
    assert state == CadenceState(
        agent_id="never-seen",
        last_compile_at=None,
        skill_count_at_last_compile=0,
        manual_trigger_pending=False,
    )


# --------------------------------------------------------------------------- lock


@pytest.mark.asyncio
async def test_lock_second_caller_skips(tmp_path: Path) -> None:
    c = _controller(tmp_path)
    assert await c.try_acquire("investigation") is True
    assert await c.try_acquire("investigation") is False  # in flight
    c.release("investigation")


@pytest.mark.asyncio
async def test_lock_reacquire_after_release(tmp_path: Path) -> None:
    c = _controller(tmp_path)
    assert await c.try_acquire("investigation") is True
    c.release("investigation")
    assert await c.try_acquire("investigation") is True
    c.release("investigation")


@pytest.mark.asyncio
async def test_lock_is_per_agent(tmp_path: Path) -> None:
    c = _controller(tmp_path)
    assert await c.try_acquire("investigation") is True
    assert await c.try_acquire("remediation") is True  # different agent → independent
    c.release("investigation")
    c.release("remediation")


@pytest.mark.asyncio
async def test_release_is_idempotent(tmp_path: Path) -> None:
    c = _controller(tmp_path)
    assert await c.try_acquire("investigation") is True
    c.release("investigation")
    c.release("investigation")  # no-op, no error
    assert await c.try_acquire("investigation") is True
    c.release("investigation")
