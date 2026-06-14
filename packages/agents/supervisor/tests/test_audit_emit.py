"""Tests — `supervisor.audit_emit` (Task 9).

10 tests covering the 4 additive F.6 audit-action vocabulary
entries + their helper invocations:

1.  ``SUPERVISOR_AUDIT_ACTIONS`` set carries exactly the 4 entries.
2.  Each action constant is the documented string verbatim.
3.  ``emit_heartbeat_started`` writes the expected payload shape.
4.  ``emit_heartbeat_started`` counts triggers by source (events /
    CLI / scheduled-queue).
5.  ``emit_delegation_dispatched`` writes the expected payload shape.
6.  ``emit_delegation_completed`` writes status + duration + reason.
7.  ``emit_delegation_completed`` for OK outcome omits the ``reason``
    key (reason is None on OK per schema invariant).
8.  ``emit_escalation_raised`` writes the escalation markdown path.
9.  ``emit_escalation_raised`` allows ``escalation_markdown_path=None``
    (when the markdown writer hasn't been called yet — e.g. dry-run
    scenarios in tests).
10. F.6 hash-chain semantics preserved — emitting multiple actions
    yields entries whose ``previous_hash`` chains correctly.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from charter.audit import GENESIS_HASH, AuditLog
from supervisor.audit_emit import (
    ACTION_DELEGATION_COMPLETED,
    ACTION_DELEGATION_DISPATCHED,
    ACTION_ESCALATION_RAISED,
    ACTION_HEARTBEAT_STARTED,
    SUPERVISOR_AUDIT_ACTIONS,
    emit_delegation_completed,
    emit_delegation_dispatched,
    emit_escalation_raised,
    emit_heartbeat_started,
)
from supervisor.schemas import (
    DelegationContract,
    DelegationOutcome,
    DelegationStatus,
    EscalationNotice,
    IncomingTask,
    TriggerSource,
)

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


def _audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", agent="supervisor", run_id="tick1")


def _read_entries(path: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


def test_supervisor_audit_actions_set_contains_original_four() -> None:
    # Additive growth: v0.2 (Q4) → 8, v0.3 (Track D D-2) → 9; the original 4
    # entries remain (WI-O5).
    assert {
        ACTION_HEARTBEAT_STARTED,
        ACTION_DELEGATION_DISPATCHED,
        ACTION_DELEGATION_COMPLETED,
        ACTION_ESCALATION_RAISED,
    } <= SUPERVISOR_AUDIT_ACTIONS
    assert len(SUPERVISOR_AUDIT_ACTIONS) == 9


def test_action_constants_match_documented_strings() -> None:
    """Per ADR-010 additive condition: these strings are the
    canonical vocabulary; renaming would break the audit chain
    consumer contract."""
    assert ACTION_HEARTBEAT_STARTED == "supervisor.heartbeat.started"
    assert ACTION_DELEGATION_DISPATCHED == "supervisor.delegation.dispatched"
    assert ACTION_DELEGATION_COMPLETED == "supervisor.delegation.completed"
    assert ACTION_ESCALATION_RAISED == "supervisor.escalation.raised"


# ---------------------------------------------------------------------------
# emit_heartbeat_started
# ---------------------------------------------------------------------------


def test_heartbeat_started_writes_expected_payload(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    triggers = [
        IncomingTask(
            task_id="t1",
            customer_id="acme",
            trigger_source=TriggerSource.OPERATOR_CLI,
            received_at=_NOW,
        ),
    ]
    emit_heartbeat_started(log, customer_id="acme", tick_id="tick1", triggers=triggers)
    entries = _read_entries(log.path)
    assert len(entries) == 1
    assert entries[0]["action"] == "supervisor.heartbeat.started"
    payload = entries[0]["payload"]
    assert payload["customer_id"] == "acme"
    assert payload["tick_id"] == "tick1"
    assert payload["trigger_count_total"] == 1


def test_heartbeat_started_counts_triggers_by_source(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    triggers = [
        IncomingTask(
            task_id="t1", customer_id="a", trigger_source=TriggerSource.EVENTS_BUS, received_at=_NOW
        ),
        IncomingTask(
            task_id="t2", customer_id="a", trigger_source=TriggerSource.EVENTS_BUS, received_at=_NOW
        ),
        IncomingTask(
            task_id="t3",
            customer_id="a",
            trigger_source=TriggerSource.SCHEDULED_QUEUE,
            received_at=_NOW,
        ),
    ]
    emit_heartbeat_started(log, customer_id="a", tick_id="tick1", triggers=triggers)
    payload = _read_entries(log.path)[0]["payload"]
    assert payload["triggers_by_source"] == {"events_bus": 2, "scheduled_queue": 1}


# ---------------------------------------------------------------------------
# emit_delegation_dispatched
# ---------------------------------------------------------------------------


def test_delegation_dispatched_payload_shape(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    contract = DelegationContract(
        delegation_id="d1",
        customer_id="acme",
        target_agent="cloud_posture",
        task_id="t1",
        budget_wall_clock_sec=60.0,
        budget_max_tool_calls=20,
        created_at=_NOW,
    )
    emit_delegation_dispatched(log, contract=contract, rule_id="r_explicit")
    payload = _read_entries(log.path)[0]["payload"]
    assert payload == {
        "customer_id": "acme",
        "delegation_id": "d1",
        "target_agent": "cloud_posture",
        "task_id": "t1",
        "rule_id": "r_explicit",
        "budget_wall_clock_sec": 60.0,
        "budget_max_tool_calls": 20,
    }


# ---------------------------------------------------------------------------
# emit_delegation_completed
# ---------------------------------------------------------------------------


def test_delegation_completed_with_reason(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    outcome = DelegationOutcome(
        delegation_id="d1",
        target_agent="cloud_posture",
        status=DelegationStatus.TIMEOUT_PARTIAL,
        duration_sec=60.0,
        reason="timeout after 60s",
        completed_at=_NOW,
    )
    emit_delegation_completed(log, outcome=outcome, customer_id="acme")
    payload = _read_entries(log.path)[0]["payload"]
    assert payload["status"] == "timeout_partial"
    assert payload["duration_sec"] == 60.0
    assert payload["reason"] == "timeout after 60s"


def test_delegation_completed_ok_omits_reason(tmp_path: Path) -> None:
    """Schema invariant: OK outcomes have reason=None. The audit
    payload should omit the reason key entirely on OK to keep the
    serialized form compact + non-misleading."""
    log = _audit_log(tmp_path)
    outcome = DelegationOutcome(
        delegation_id="d1",
        target_agent="cloud_posture",
        status=DelegationStatus.OK,
        duration_sec=1.0,
        completed_at=_NOW,
    )
    emit_delegation_completed(log, outcome=outcome, customer_id="acme")
    payload = _read_entries(log.path)[0]["payload"]
    assert payload["status"] == "ok"
    assert "reason" not in payload


# ---------------------------------------------------------------------------
# emit_escalation_raised
# ---------------------------------------------------------------------------


def test_escalation_raised_with_markdown_path(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    notice = EscalationNotice(
        escalation_id="esc1",
        customer_id="acme",
        task_id="t1",
        reason="no rule matched",
        raised_at=_NOW,
    )
    md_path = tmp_path / "escalation_esc1.md"
    emit_escalation_raised(log, notice=notice, escalation_markdown_path=md_path)
    payload = _read_entries(log.path)[0]["payload"]
    assert payload["escalation_id"] == "esc1"
    assert payload["reason"] == "no rule matched"
    assert payload["escalation_markdown"] == str(md_path)


def test_escalation_raised_without_markdown_path(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    notice = EscalationNotice(
        escalation_id="esc1",
        customer_id="acme",
        task_id="t1",
        reason="boom",
        raised_at=_NOW,
    )
    emit_escalation_raised(log, notice=notice, escalation_markdown_path=None)
    payload = _read_entries(log.path)[0]["payload"]
    assert "escalation_markdown" not in payload


# ---------------------------------------------------------------------------
# Hash-chain preservation
# ---------------------------------------------------------------------------


def test_hash_chain_preserved_across_multiple_emits(tmp_path: Path) -> None:
    """F.6 invariant: each entry's previous_hash equals the prior
    entry's entry_hash. Smoke probe across three sequential emits."""
    log = _audit_log(tmp_path)
    emit_heartbeat_started(log, customer_id="acme", tick_id="tick1", triggers=())
    contract = DelegationContract(
        delegation_id="d1",
        customer_id="acme",
        target_agent="cloud_posture",
        task_id="t1",
        budget_wall_clock_sec=60.0,
        budget_max_tool_calls=20,
        created_at=_NOW,
    )
    emit_delegation_dispatched(log, contract=contract, rule_id="r1")
    outcome = DelegationOutcome(
        delegation_id="d1",
        target_agent="cloud_posture",
        status=DelegationStatus.OK,
        duration_sec=1.0,
        completed_at=_NOW,
    )
    emit_delegation_completed(log, outcome=outcome, customer_id="acme")

    entries = _read_entries(log.path)
    assert len(entries) == 3
    assert entries[0]["previous_hash"] == GENESIS_HASH
    assert entries[1]["previous_hash"] == entries[0]["entry_hash"]
    assert entries[2]["previous_hash"] == entries[1]["entry_hash"]
