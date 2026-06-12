"""supervisor v0.2 Task 13 — event-bus trigger listener tests (Q6/WI-O10)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from supervisor.schemas import TriggerSource
from supervisor.triggers.event_bus import (
    EventBusListener,
    ForbiddenEventSubscriptionError,
    assert_subscription_allowed,
    event_to_task,
)

_NOW = datetime(2026, 6, 1, tzinfo=UTC)


def test_events_subscription_allowed() -> None:
    assert_subscription_allowed("events.tenant.c1.>")  # does not raise


def test_claims_subscription_rejected() -> None:
    with pytest.raises(ForbiddenEventSubscriptionError, match="claims"):
        assert_subscription_allowed("claims.>")


def test_claims_prefix_rejected() -> None:
    with pytest.raises(ForbiddenEventSubscriptionError):
        assert_subscription_allowed("claims.tenant.c1.agent.curiosity")


def test_listener_constructs_with_events() -> None:
    listener = EventBusListener(subscriptions=["events.>", "events.tenant.c1.>"])
    assert listener.subscriptions == ("events.>", "events.tenant.c1.>")


def test_listener_rejects_claims_at_construction() -> None:
    with pytest.raises(ForbiddenEventSubscriptionError):
        EventBusListener(subscriptions=["events.>", "claims.>"])


def test_event_to_task_maps_routing_keys() -> None:
    task = event_to_task(
        {"task_id": "t1", "customer_id": "c1", "target_agent": "compliance", "task_type": "scan"},
        now=_NOW,
    )
    assert task.trigger_source == TriggerSource.EVENTS_BUS
    assert task.target_agent == "compliance" and task.task_type == "scan"


def test_event_to_task_ignores_payload_body() -> None:
    # WI-4: only routing keys are read; an OCSF body must not leak into the task envelope.
    task = event_to_task(
        {"task_id": "t1", "customer_id": "c1", "finding_body": {"secret": "xyz"}}, now=_NOW
    )
    assert "xyz" not in (task.description or "")
    assert task.target_agent is None


def test_listener_ingest() -> None:
    listener = EventBusListener(subscriptions=["events.>"])
    task = listener.ingest({"task_id": "t1", "customer_id": "c1"}, now=_NOW)
    assert task.task_id == "t1" and task.trigger_source == TriggerSource.EVENTS_BUS
