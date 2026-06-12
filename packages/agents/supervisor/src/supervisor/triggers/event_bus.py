"""Event-bus trigger listener (supervisor v0.2 Task 13, Q6/WI-O10).

Ingests F.7 ``events.>`` messages into ``IncomingTask`` envelopes (trigger_source EVENTS_BUS),
alongside the heartbeat path. Reads **only the routing keys** (target_agent / task_type /
delta_type) — never the OCSF payload body (the WI-4 read-only contract). Per **WI-O10** the
listener **must never** subscribe to ``claims.>``: ``assert_subscription_allowed`` enforces the
fence at construction, mirroring the substrate ``_FORBIDDEN_SUBSCRIPTIONS`` guard so a router
can never launder speculation into action.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from supervisor.schemas import IncomingTask, TriggerSource

EVENTS_PREFIX = "events."
FORBIDDEN_PREFIX = "claims."


class ForbiddenEventSubscriptionError(RuntimeError):
    """Raised when an event subscription would reach ``claims.>`` (WI-O10)."""


def assert_subscription_allowed(subject: str) -> None:
    """The supervisor listens on ``events.>`` only — any ``claims.>`` subject is rejected."""
    if subject == "claims.>" or subject.startswith(FORBIDDEN_PREFIX):
        raise ForbiddenEventSubscriptionError(
            f"subscription {subject!r} is forbidden — supervisor must never subscribe to "
            f"claims.> (WI-O10 / _FORBIDDEN_SUBSCRIPTIONS fence). Only events.> is allowed."
        )


def event_to_task(event: Mapping[str, Any], *, now: datetime) -> IncomingTask:
    """Map an event envelope to an ``IncomingTask`` using routing keys only (never the body)."""
    return IncomingTask(
        task_id=str(event["task_id"]),
        customer_id=str(event["customer_id"]),
        trigger_source=TriggerSource.EVENTS_BUS,
        target_agent=_opt(event.get("target_agent")),
        task_type=_opt(event.get("task_type")),
        delta_type=_opt(event.get("delta_type")),
        description=str(event.get("description", "")),
        priority=int(event.get("priority", 0)),
        received_at=now,
    )


def _opt(value: Any) -> str | None:
    return None if value is None else str(value)


class EventBusListener:
    """Validates its subscriptions against the fence and converts events to tasks."""

    __slots__ = ("_subscriptions",)

    def __init__(self, *, subscriptions: Sequence[str]) -> None:
        for subject in subscriptions:
            assert_subscription_allowed(subject)
        self._subscriptions = tuple(subscriptions)

    @property
    def subscriptions(self) -> tuple[str, ...]:
        return self._subscriptions

    def ingest(self, event: Mapping[str, Any], *, now: datetime) -> IncomingTask:
        return event_to_task(event, now=now)
