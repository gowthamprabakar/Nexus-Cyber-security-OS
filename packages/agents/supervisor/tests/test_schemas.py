"""Tests — `supervisor.schemas` (Task 2).

18 tests covering each pydantic type + their invariants:

- IncomingTask — required envelope fields; metadata-only.
- RoutingRule — at-least-one-match-predicate invariant;
  permitted_tools validation.
- RoutingMatch / NoMatch / Ambiguous / Escalate — tagged-union
  variants with discriminator.
- DelegationContract — bounded budget fields.
- DelegationOutcome — XOR reason / status invariant.
- EscalationNotice — required fields.
- SupervisorReport — top-level holder with computed properties.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError
from supervisor.schemas import (
    MAX_PARALLEL_DISPATCH,
    DelegationContract,
    DelegationOutcome,
    DelegationStatus,
    EscalationNotice,
    IncomingTask,
    RoutingAmbiguous,
    RoutingDecision,
    RoutingEscalate,
    RoutingMatch,
    RoutingNoMatch,
    RoutingRule,
    SupervisorReport,
    TriggerSource,
)

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# IncomingTask
# ---------------------------------------------------------------------------


def test_incoming_task_minimal_valid() -> None:
    task = IncomingTask(
        task_id="t1",
        customer_id="acme",
        trigger_source=TriggerSource.OPERATOR_CLI,
        received_at=_NOW,
    )
    assert task.target_agent is None
    assert task.priority == 0


def test_incoming_task_with_explicit_target_agent() -> None:
    task = IncomingTask(
        task_id="t1",
        customer_id="acme",
        trigger_source=TriggerSource.EVENTS_BUS,
        target_agent="cloud_posture",
        task_type="scan",
        received_at=_NOW,
    )
    assert task.target_agent == "cloud_posture"


# ---------------------------------------------------------------------------
# RoutingRule
# ---------------------------------------------------------------------------


def test_routing_rule_valid_with_target_agent_declared() -> None:
    rule = RoutingRule(
        rule_id="r1",
        target_agent="cloud_posture",
        target_agent_declared="cloud_posture",
        permitted_tools=("prowler_scan", "aws_s3_describe"),
    )
    assert rule.target_agent == "cloud_posture"


def test_routing_rule_requires_at_least_one_match_predicate() -> None:
    with pytest.raises(ValidationError, match="at least one match predicate"):
        RoutingRule(rule_id="r1", target_agent="cloud_posture")


def test_routing_rule_rejects_empty_permitted_tool_name() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        RoutingRule(
            rule_id="r1",
            target_agent="x",
            target_agent_declared="x",
            permitted_tools=("valid", ""),
        )


# ---------------------------------------------------------------------------
# RoutingDecision tagged union
# ---------------------------------------------------------------------------


def test_routing_match_variant() -> None:
    decision = RoutingMatch(
        rule_id="r1",
        target_agent="cloud_posture",
        permitted_tools=("prowler_scan",),
    )
    assert decision.kind == "match"


def test_routing_no_match_variant() -> None:
    decision = RoutingNoMatch(reason="no rule matched")
    assert decision.kind == "no_match"


def test_routing_ambiguous_variant_requires_two_candidates() -> None:
    decision = RoutingAmbiguous(
        candidate_rule_ids=("r1", "r2"),
        reason="two rules matched at same priority",
    )
    assert decision.kind == "ambiguous"
    with pytest.raises(ValidationError):
        RoutingAmbiguous(candidate_rule_ids=("r1",), reason="only one")


def test_routing_escalate_variant() -> None:
    decision = RoutingEscalate(rule_id="r1", reason="explicit escalate terminal")
    assert decision.kind == "escalate"


def test_routing_decision_tagged_union_discriminates_by_kind() -> None:
    """The tagged-union discriminator routes correctly across variants."""
    adapter = TypeAdapter(RoutingDecision)
    parsed = adapter.validate_python({"kind": "match", "rule_id": "r1", "target_agent": "x"})
    assert isinstance(parsed, RoutingMatch)
    parsed_nm = adapter.validate_python({"kind": "no_match", "reason": "nope"})
    assert isinstance(parsed_nm, RoutingNoMatch)


# ---------------------------------------------------------------------------
# DelegationContract
# ---------------------------------------------------------------------------


def test_delegation_contract_valid() -> None:
    contract = DelegationContract(
        delegation_id="d1",
        customer_id="acme",
        target_agent="cloud_posture",
        task_id="t1",
        budget_wall_clock_sec=60.0,
        budget_max_tool_calls=20,
        created_at=_NOW,
    )
    assert contract.budget_wall_clock_sec == 60.0


def test_delegation_contract_rejects_zero_budget() -> None:
    with pytest.raises(ValidationError):
        DelegationContract(
            delegation_id="d1",
            customer_id="acme",
            target_agent="x",
            task_id="t1",
            budget_wall_clock_sec=0.0,
            budget_max_tool_calls=20,
            created_at=_NOW,
        )


# ---------------------------------------------------------------------------
# DelegationOutcome
# ---------------------------------------------------------------------------


def test_delegation_outcome_ok_no_reason_required() -> None:
    outcome = DelegationOutcome(
        delegation_id="d1",
        target_agent="cloud_posture",
        status=DelegationStatus.OK,
        duration_sec=1.5,
        completed_at=_NOW,
    )
    assert outcome.reason is None


def test_delegation_outcome_timeout_partial_requires_reason() -> None:
    with pytest.raises(ValidationError, match="reason required"):
        DelegationOutcome(
            delegation_id="d1",
            target_agent="x",
            status=DelegationStatus.TIMEOUT_PARTIAL,
            duration_sec=60.0,
            completed_at=_NOW,
        )


def test_delegation_outcome_error_requires_reason() -> None:
    outcome = DelegationOutcome(
        delegation_id="d1",
        target_agent="x",
        status=DelegationStatus.ERROR,
        duration_sec=0.1,
        reason="ImportError",
        completed_at=_NOW,
    )
    assert outcome.status == DelegationStatus.ERROR


# ---------------------------------------------------------------------------
# EscalationNotice
# ---------------------------------------------------------------------------


def test_escalation_notice_valid() -> None:
    e = EscalationNotice(
        escalation_id="esc1",
        customer_id="acme",
        task_id="t1",
        reason="no routing rule matched",
        raised_at=_NOW,
    )
    assert e.escalation_id == "esc1"


# ---------------------------------------------------------------------------
# SupervisorReport
# ---------------------------------------------------------------------------


def test_supervisor_report_minimal_valid() -> None:
    report = SupervisorReport(
        customer_id="acme",
        tick_id="tick1",
        tick_started_at=_NOW,
        tick_completed_at=_NOW,
    )
    assert report.total_triggers == 0
    assert report.total_delegations == 0
    assert report.total_escalations == 0
    assert report.successful_delegations == 0
    assert report.schema_version == "supervisor.v0.1"


def test_supervisor_report_counts_reflect_inputs() -> None:
    task = IncomingTask(
        task_id="t1",
        customer_id="acme",
        trigger_source=TriggerSource.OPERATOR_CLI,
        received_at=_NOW,
    )
    ok = DelegationOutcome(
        delegation_id="d1",
        target_agent="x",
        status=DelegationStatus.OK,
        duration_sec=1.0,
        completed_at=_NOW,
    )
    failed = DelegationOutcome(
        delegation_id="d2",
        target_agent="y",
        status=DelegationStatus.ERROR,
        duration_sec=0.5,
        reason="boom",
        completed_at=_NOW,
    )
    esc = EscalationNotice(
        escalation_id="esc1",
        customer_id="acme",
        task_id="t1",
        reason="boom",
        raised_at=_NOW,
    )
    report = SupervisorReport(
        customer_id="acme",
        tick_id="tick1",
        tick_started_at=_NOW,
        tick_completed_at=_NOW,
        triggers_received=(task,),
        delegations=(ok, failed),
        escalations=(esc,),
    )
    assert report.total_triggers == 1
    assert report.total_delegations == 2
    assert report.successful_delegations == 1
    assert report.total_escalations == 1


def test_max_parallel_dispatch_constant() -> None:
    """v0.1 cap per Q3."""
    assert MAX_PARALLEL_DISPATCH == 5
