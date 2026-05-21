"""Tests — `supervisor.routing.router` (Task 4).

14 tests covering the pure-function rule engine:

1.  Empty rules + any task -> NoMatch.
2.  Explicit target_agent matches the rule via target_agent_declared.
3.  Explicit target_agent on task wins over task_type/delta_type
    fallbacks (precedence #1).
4.  task_type pattern-match fallback when no target_agent declared.
5.  delta_type pattern-match fallback when no target_agent and no
    task_type.
6.  Two rules match explicit; higher priority wins.
7.  Two rules match explicit at same priority -> Ambiguous.
8.  Three rules at mixed priorities + tie at the top -> Ambiguous
    with only the top-priority rule_ids in the candidate list.
9.  Task with NO routing keys -> NoMatch.
10. NoMatch.reason carries the task's routing keys for triage.
11. Ambiguous.candidate_rule_ids preserves rule order in the tie set.
12. Match.permitted_tools propagates from the rule.
13. Precedence: a rule that matches task_type does NOT win against
    a rule that matches target_agent_declared.
14. Bundled `agents.md` rules route each v0.1 specialist correctly
    when invoked with the matching explicit IncomingTask.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from supervisor.routing.parser import load_routing_rules
from supervisor.routing.router import route
from supervisor.schemas import (
    IncomingTask,
    RoutingAmbiguous,
    RoutingMatch,
    RoutingNoMatch,
    RoutingRule,
    TriggerSource,
)

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)
_BUNDLED_AGENTS_MD = (
    Path(__file__).resolve().parent.parent / "src" / "supervisor" / "routing" / "agents.md"
)


def _task(
    *,
    target_agent: str | None = None,
    task_type: str | None = None,
    delta_type: str | None = None,
) -> IncomingTask:
    return IncomingTask(
        task_id="t1",
        customer_id="acme",
        trigger_source=TriggerSource.OPERATOR_CLI,
        target_agent=target_agent,
        task_type=task_type,
        delta_type=delta_type,
        received_at=_NOW,
    )


def _rule(
    rule_id: str,
    *,
    target_agent: str = "agent_x",
    target_agent_declared: str | None = None,
    task_type_pattern: str | None = None,
    delta_type_pattern: str | None = None,
    priority: int = 0,
    permitted_tools: tuple[str, ...] = (),
) -> RoutingRule:
    return RoutingRule(
        rule_id=rule_id,
        target_agent=target_agent,
        target_agent_declared=target_agent_declared,
        task_type_pattern=task_type_pattern,
        delta_type_pattern=delta_type_pattern,
        priority=priority,
        permitted_tools=permitted_tools,
    )


# ---------------------------------------------------------------------------
# Core paths
# ---------------------------------------------------------------------------


def test_empty_rules_yields_no_match() -> None:
    decision = route(_task(target_agent="x"), rules=())
    assert isinstance(decision, RoutingNoMatch)


def test_explicit_target_agent_matches() -> None:
    rule = _rule("r1", target_agent="cloud_posture", target_agent_declared="cloud_posture")
    decision = route(_task(target_agent="cloud_posture"), [rule])
    assert isinstance(decision, RoutingMatch)
    assert decision.target_agent == "cloud_posture"
    assert decision.rule_id == "r1"


def test_explicit_wins_over_task_type_fallback() -> None:
    """Precedence #1 beats #2 — explicit routing always wins."""
    explicit = _rule(
        "r_explicit",
        target_agent="cloud_posture",
        target_agent_declared="cloud_posture",
    )
    task_type_rule = _rule(
        "r_pattern",
        target_agent="vulnerability",
        task_type_pattern="scan",
    )
    decision = route(
        _task(target_agent="cloud_posture", task_type="scan"),
        [task_type_rule, explicit],  # order doesn't matter
    )
    assert isinstance(decision, RoutingMatch)
    assert decision.target_agent == "cloud_posture"


def test_task_type_fallback_when_no_explicit() -> None:
    rule = _rule("r1", target_agent="vulnerability", task_type_pattern="scan")
    decision = route(_task(task_type="scan"), [rule])
    assert isinstance(decision, RoutingMatch)
    assert decision.target_agent == "vulnerability"


def test_delta_type_fallback_when_no_explicit_or_task_type() -> None:
    rule = _rule("r1", target_agent="cloud_posture", delta_type_pattern="S3_misconfiguration")
    decision = route(_task(delta_type="S3_misconfiguration"), [rule])
    assert isinstance(decision, RoutingMatch)
    assert decision.target_agent == "cloud_posture"


# ---------------------------------------------------------------------------
# Priority resolution
# ---------------------------------------------------------------------------


def test_higher_priority_wins() -> None:
    low = _rule(
        "r_low",
        target_agent="agent_a",
        target_agent_declared="x",
        priority=1,
    )
    high = _rule(
        "r_high",
        target_agent="agent_b",
        target_agent_declared="x",
        priority=10,
    )
    decision = route(_task(target_agent="x"), [low, high])
    assert isinstance(decision, RoutingMatch)
    assert decision.rule_id == "r_high"
    assert decision.target_agent == "agent_b"


def test_tie_at_same_priority_yields_ambiguous() -> None:
    a = _rule("r_a", target_agent="agent_a", target_agent_declared="x", priority=5)
    b = _rule("r_b", target_agent="agent_b", target_agent_declared="x", priority=5)
    decision = route(_task(target_agent="x"), [a, b])
    assert isinstance(decision, RoutingAmbiguous)
    assert set(decision.candidate_rule_ids) == {"r_a", "r_b"}


def test_ambiguous_only_lists_top_priority_candidates() -> None:
    low = _rule("r_low", target_agent="a", target_agent_declared="x", priority=1)
    high_a = _rule("r_high_a", target_agent="b", target_agent_declared="x", priority=10)
    high_b = _rule("r_high_b", target_agent="c", target_agent_declared="x", priority=10)
    decision = route(_task(target_agent="x"), [low, high_a, high_b])
    assert isinstance(decision, RoutingAmbiguous)
    assert "r_low" not in decision.candidate_rule_ids
    assert set(decision.candidate_rule_ids) == {"r_high_a", "r_high_b"}


def test_ambiguous_preserves_rule_order_in_candidates() -> None:
    a = _rule("r_a", target_agent="a", target_agent_declared="x", priority=5)
    b = _rule("r_b", target_agent="b", target_agent_declared="x", priority=5)
    decision = route(_task(target_agent="x"), [a, b])
    assert isinstance(decision, RoutingAmbiguous)
    assert decision.candidate_rule_ids == ("r_a", "r_b")


# ---------------------------------------------------------------------------
# NoMatch + Match payload
# ---------------------------------------------------------------------------


def test_task_with_no_routing_keys_yields_no_match() -> None:
    decision = route(_task(), rules=())
    assert isinstance(decision, RoutingNoMatch)
    assert "no routing keys" in decision.reason.lower()


def test_no_match_reason_carries_routing_keys() -> None:
    decision = route(_task(target_agent="ghost", task_type="scan"), rules=())
    assert isinstance(decision, RoutingNoMatch)
    assert "ghost" in decision.reason
    assert "scan" in decision.reason


def test_match_permitted_tools_propagates() -> None:
    rule = _rule(
        "r1",
        target_agent="cloud_posture",
        target_agent_declared="cloud_posture",
        permitted_tools=("prowler_scan", "aws_s3_describe"),
    )
    decision = route(_task(target_agent="cloud_posture"), [rule])
    assert isinstance(decision, RoutingMatch)
    assert decision.permitted_tools == ("prowler_scan", "aws_s3_describe")


# ---------------------------------------------------------------------------
# Precedence non-overlap
# ---------------------------------------------------------------------------


def test_task_type_rule_does_not_win_against_explicit_rule() -> None:
    """Even at a higher priority, a task_type-only rule does not
    win when an explicit rule matches the task's target_agent."""
    explicit = _rule(
        "r_explicit",
        target_agent="cloud_posture",
        target_agent_declared="cloud_posture",
        priority=1,
    )
    task_type_high = _rule(
        "r_task_type",
        target_agent="vulnerability",
        task_type_pattern="scan",
        priority=100,
    )
    decision = route(
        _task(target_agent="cloud_posture", task_type="scan"),
        [task_type_high, explicit],
    )
    assert isinstance(decision, RoutingMatch)
    assert decision.target_agent == "cloud_posture"


# ---------------------------------------------------------------------------
# Bundled agents.md integration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "agent_id",
    [
        "cloud_posture",
        "vulnerability",
        "identity",
        "runtime_threat",
        "audit",
        "investigation",
        "network_threat",
        "multi_cloud_posture",
        "k8s_posture",
        "remediation",
    ],
)
def test_bundled_agents_md_routes_each_specialist(agent_id: str) -> None:
    rules = load_routing_rules(_BUNDLED_AGENTS_MD)
    decision = route(_task(target_agent=agent_id), rules)
    assert isinstance(decision, RoutingMatch)
    assert decision.target_agent == agent_id
