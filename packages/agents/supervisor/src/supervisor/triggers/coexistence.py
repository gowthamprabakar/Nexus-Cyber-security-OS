"""Heartbeat + event-driven coexistence (supervisor v0.2 Task 14, Q6).

Per **Q6** both trigger modes are available and **neither preempts the other** at v0.2:
HEARTBEAT (the v0.1 tick path) stays the default; EVENT_DRIVEN adds the Task-13 event listener
on top. The mode is a **selection flag only** — it governs *when* a task arrives, never *how*
it routes — so a task ingested via either mode produces an **identical** routing decision (the
routing keys are the same; ``trigger_source`` is not a routing input). Per **WI-O2** this is
INFRASTRUCTURE; wiring event-driven preemption into the production loop is the Phase C retrofit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any

from supervisor.routing.router import route
from supervisor.schemas import IncomingTask, RoutingDecision, RoutingRule

TRIGGER_MODE_CONFIG_KEY = "supervisor_trigger_mode"


class TriggerMode(StrEnum):
    HEARTBEAT = "heartbeat"
    EVENT_DRIVEN = "event_driven"


#: HEARTBEAT is the default — EVENT_DRIVEN never preempts it at v0.2 (Q6).
DEFAULT_TRIGGER_MODE = TriggerMode.HEARTBEAT


def select_trigger_mode(config: Mapping[str, Any]) -> TriggerMode:
    """Resolve the trigger mode from a config flag; unknown/missing -> the default."""
    raw = config.get(TRIGGER_MODE_CONFIG_KEY)
    if isinstance(raw, str):
        try:
            return TriggerMode(raw.lower())
        except ValueError:
            return DEFAULT_TRIGGER_MODE
    return DEFAULT_TRIGGER_MODE


def modes_coexist() -> bool:
    """Both trigger modes are always available; neither preempts the other (Q6)."""
    return True


def route_decision(task: IncomingTask, rules: Sequence[RoutingRule]) -> RoutingDecision:
    """Route a task. The decision depends only on routing keys, never ``trigger_source`` — so
    HEARTBEAT and EVENT_DRIVEN ingestion of the same task route identically."""
    return route(task, rules)
