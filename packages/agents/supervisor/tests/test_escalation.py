"""Tests — `supervisor.escalation` (Task 6).

8 tests covering both escalation paths:

1.  ``build_routing_escalation(RoutingMatch)`` -> None (Match
    path dispatches; no escalation).
2.  ``build_routing_escalation(RoutingNoMatch)`` -> EscalationNotice
    with NoMatch.reason.
3.  ``build_routing_escalation(RoutingAmbiguous)`` -> EscalationNotice
    with the Ambiguous.reason text.
4.  ``build_routing_escalation(RoutingEscalate)`` -> EscalationNotice
    with the Escalate.reason text.
5.  ``build_delegation_escalation(status=OK)`` -> None.
6.  ``build_delegation_escalation(status=TIMEOUT_PARTIAL)`` ->
    EscalationNotice carrying target_agent + reason.
7.  ``write_escalation_markdown`` writes to
    ``<workspace_root>/escalation_<id>.md`` with required sections.
8.  Each ``escalation_id`` is a valid ULID + unique across calls
    (idempotent across reruns is NOT the contract — ULIDs are
    fresh per call; the audit chain preserves history).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import ulid
from supervisor.escalation import (
    build_delegation_escalation,
    build_routing_escalation,
    write_escalation_markdown,
)
from supervisor.schemas import (
    DelegationOutcome,
    DelegationStatus,
    RoutingAmbiguous,
    RoutingEscalate,
    RoutingMatch,
    RoutingNoMatch,
)

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


def test_routing_match_yields_no_escalation() -> None:
    decision = RoutingMatch(rule_id="r1", target_agent="cloud_posture")
    assert build_routing_escalation(decision, customer_id="acme", task_id="t1") is None


def test_routing_no_match_yields_escalation() -> None:
    decision = RoutingNoMatch(reason="no rule matched task with target_agent='ghost'")
    notice = build_routing_escalation(decision, customer_id="acme", task_id="t1")
    assert notice is not None
    assert notice.customer_id == "acme"
    assert notice.task_id == "t1"
    assert "ghost" in notice.reason


def test_routing_ambiguous_yields_escalation() -> None:
    decision = RoutingAmbiguous(
        candidate_rule_ids=("r_a", "r_b"),
        reason="2 rules matched at priority=10",
    )
    notice = build_routing_escalation(decision, customer_id="acme", task_id="t1")
    assert notice is not None
    assert "priority=10" in notice.reason


def test_routing_escalate_yields_escalation() -> None:
    decision = RoutingEscalate(rule_id="r1", reason="explicit terminal")
    notice = build_routing_escalation(decision, customer_id="acme", task_id="t1")
    assert notice is not None
    assert notice.reason == "explicit terminal"


def test_delegation_ok_yields_no_escalation() -> None:
    outcome = DelegationOutcome(
        delegation_id="d1",
        target_agent="cloud_posture",
        status=DelegationStatus.OK,
        duration_sec=1.0,
        completed_at=_NOW,
    )
    assert build_delegation_escalation(outcome, customer_id="acme", task_id="t1") is None


def test_delegation_timeout_partial_yields_escalation() -> None:
    outcome = DelegationOutcome(
        delegation_id="d1",
        target_agent="cloud_posture",
        status=DelegationStatus.TIMEOUT_PARTIAL,
        duration_sec=60.0,
        reason="timeout after 60s",
        completed_at=_NOW,
    )
    notice = build_delegation_escalation(outcome, customer_id="acme", task_id="t1")
    assert notice is not None
    assert "cloud_posture" in notice.reason
    assert "timeout" in notice.reason.lower()


def test_write_escalation_markdown_writes_file(tmp_path: Path) -> None:
    notice = build_routing_escalation(
        RoutingNoMatch(reason="no rule matched"),
        customer_id="acme",
        task_id="t1",
    )
    assert notice is not None
    path = write_escalation_markdown(notice, workspace_root=tmp_path)
    assert path.is_file()
    assert path.name == f"escalation_{notice.escalation_id}.md"

    body = path.read_text(encoding="utf-8")
    assert f"`{notice.escalation_id}`" in body
    assert "`acme`" in body
    assert "`t1`" in body
    assert "no rule matched" in body
    assert "does not auto-retry" in body


def test_escalation_ids_are_unique_valid_ulids() -> None:
    """ULID per call; never collides across two calls."""
    notice_a = build_routing_escalation(
        RoutingNoMatch(reason="a"),
        customer_id="acme",
        task_id="t1",
    )
    notice_b = build_routing_escalation(
        RoutingNoMatch(reason="b"),
        customer_id="acme",
        task_id="t1",
    )
    assert notice_a is not None
    assert notice_b is not None
    assert notice_a.escalation_id != notice_b.escalation_id
    # Each is parseable as a ULID.
    ulid.ULID.from_str(notice_a.escalation_id)
    ulid.ULID.from_str(notice_b.escalation_id)
