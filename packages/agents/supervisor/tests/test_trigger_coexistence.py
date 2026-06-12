"""supervisor v0.2 Task 14 — heartbeat + event-driven coexistence tests (Q6)."""

from __future__ import annotations

from datetime import UTC, datetime

from supervisor.schemas import IncomingTask, RoutingRule, TriggerSource
from supervisor.triggers.coexistence import (
    DEFAULT_TRIGGER_MODE,
    TriggerMode,
    modes_coexist,
    route_decision,
    select_trigger_mode,
)

_NOW = datetime(2026, 6, 1, tzinfo=UTC)


def _task(trigger: TriggerSource) -> IncomingTask:
    return IncomingTask(
        task_id="t1",
        customer_id="c1",
        trigger_source=trigger,
        target_agent="compliance",
        received_at=_NOW,
    )


_RULES = (
    RoutingRule(
        rule_id="r1", target_agent="compliance", target_agent_declared="compliance", priority=1
    ),
)


def test_default_is_heartbeat() -> None:
    assert DEFAULT_TRIGGER_MODE == TriggerMode.HEARTBEAT
    assert select_trigger_mode({}) == TriggerMode.HEARTBEAT


def test_select_event_driven() -> None:
    assert (
        select_trigger_mode({"supervisor_trigger_mode": "event_driven"}) == TriggerMode.EVENT_DRIVEN
    )


def test_select_case_insensitive() -> None:
    assert (
        select_trigger_mode({"supervisor_trigger_mode": "EVENT_DRIVEN"}) == TriggerMode.EVENT_DRIVEN
    )


def test_invalid_falls_back() -> None:
    assert select_trigger_mode({"supervisor_trigger_mode": "bogus"}) == DEFAULT_TRIGGER_MODE


def test_modes_coexist() -> None:
    assert modes_coexist() is True


def test_same_task_routes_identically_across_modes() -> None:
    # The coexistence property: identical routing keys -> identical decision, regardless of
    # which trigger source delivered the task.
    via_heartbeat = route_decision(_task(TriggerSource.OPERATOR_CLI), _RULES)
    via_events = route_decision(_task(TriggerSource.EVENTS_BUS), _RULES)
    assert via_heartbeat == via_events


def test_unrouted_task_equivalent_across_modes() -> None:
    no_match_rules = (
        RoutingRule(rule_id="r2", target_agent="audit", target_agent_declared="audit"),
    )
    hb = route_decision(_task(TriggerSource.SCHEDULED_QUEUE), no_match_rules)
    ev = route_decision(_task(TriggerSource.EVENTS_BUS), no_match_rules)
    assert hb == ev
