"""Tests — Track D D-2 continuous state-transition audit action (additive)."""

from __future__ import annotations

import json
from pathlib import Path

from charter.audit import AuditLog
from supervisor.audit_emit import (
    ACTION_CONTINUOUS_STATE_TRANSITION,
    SUPERVISOR_AUDIT_ACTIONS,
    SUPERVISOR_AUDIT_ACTIONS_V0_1,
    SUPERVISOR_AUDIT_ACTIONS_V0_2,
    SUPERVISOR_AUDIT_ACTIONS_V0_3,
    emit_continuous_state_transition,
)


def test_v0_3_action_in_sets() -> None:
    assert ACTION_CONTINUOUS_STATE_TRANSITION == "supervisor.continuous.state_transition"
    assert ACTION_CONTINUOUS_STATE_TRANSITION in SUPERVISOR_AUDIT_ACTIONS_V0_3
    assert ACTION_CONTINUOUS_STATE_TRANSITION in SUPERVISOR_AUDIT_ACTIONS


def test_v0_1_and_v0_2_sets_unchanged() -> None:
    """ADR-010 additive-only: the prior vocabularies stay byte-identical."""
    assert (
        frozenset(
            {
                "supervisor.heartbeat.started",
                "supervisor.delegation.dispatched",
                "supervisor.delegation.completed",
                "supervisor.escalation.raised",
            }
        )
        == SUPERVISOR_AUDIT_ACTIONS_V0_1
    )
    assert (
        frozenset(
            {
                "supervisor.delegation.parallel_batch_started",
                "supervisor.delegation.retried",
                "supervisor.delegation.semaphore_wait",
                "supervisor.queue.drained",
            }
        )
        == SUPERVISOR_AUDIT_ACTIONS_V0_2
    )
    assert len(SUPERVISOR_AUDIT_ACTIONS) == 9  # 4 + 4 + 1


def test_emit_continuous_state_transition(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl", agent="supervisor", run_id="tick1")
    emit_continuous_state_transition(
        log,
        customer_id="acme",
        continuous_mode_requested=True,
        continuous_kill_switch=True,
        continuous_effective=False,
        cadence="weekly",
    )
    lines = [
        json.loads(line)
        for line in log.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 1
    entry = lines[0]
    assert entry["action"] == ACTION_CONTINUOUS_STATE_TRANSITION
    assert entry["payload"]["customer_id"] == "acme"
    assert entry["payload"]["continuous_effective"] is False
    assert entry["payload"]["continuous_kill_switch"] is True
    assert entry["payload"]["cadence"] == "weekly"
