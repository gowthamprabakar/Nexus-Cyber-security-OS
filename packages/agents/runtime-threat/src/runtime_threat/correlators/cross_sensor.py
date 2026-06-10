"""Falco + Tracee cross-sensor correlation (D.3 v0.2 Task 7).

When Falco and Tracee both observe activity in the **same container + process**, they're
reporting on the same underlying behavior. This correlator joins normalized events by
``(container_id, pid)`` so downstream emits **one** correlated finding (cross-sensor =
higher confidence) instead of two duplicates. Events with no join context stay separate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from runtime_threat.tools.falco_normalize import NormalizedFalcoEvent
from runtime_threat.tools.tracee_normalize import NormalizedTraceeEvent


@dataclass(frozen=True, slots=True)
class CorrelationKey:
    container_id: str
    pid: str


@dataclass
class CorrelatedEvent:
    key: CorrelationKey
    falco: list[NormalizedFalcoEvent] = field(default_factory=list)
    tracee: list[NormalizedTraceeEvent] = field(default_factory=list)

    @property
    def cross_sensor(self) -> bool:
        """True iff BOTH sensors fired on this container+process (higher confidence)."""
        return bool(self.falco) and bool(self.tracee)

    @property
    def event_count(self) -> int:
        return len(self.falco) + len(self.tracee)


def falco_key(ev: NormalizedFalcoEvent) -> CorrelationKey:
    return CorrelationKey(ev.enrichment.container.id, ev.enrichment.process.pid)


def tracee_key(ev: NormalizedTraceeEvent) -> CorrelationKey:
    pid = str(ev.alert.process_id) if ev.alert.process_id else ""
    return CorrelationKey(ev.alert.container_id, pid)


def correlate_sensor_events(
    falco: list[NormalizedFalcoEvent], tracee: list[NormalizedTraceeEvent]
) -> list[CorrelatedEvent]:
    """Group Falco + Tracee events by ``(container_id, pid)``. Events with no join
    context (both empty) stay as singleton groups — they cannot be correlated."""
    groups: dict[CorrelationKey, CorrelatedEvent] = {}

    def _bucket(key: CorrelationKey, kind: str, idx: int) -> CorrelatedEvent:
        if not key.container_id and not key.pid:
            key = CorrelationKey(f"_uncorrelated_{kind}_{idx}", "")
        return groups.setdefault(key, CorrelatedEvent(key=key))

    for i, f in enumerate(falco):
        _bucket(falco_key(f), "falco", i).falco.append(f)
    for i, t in enumerate(tracee):
        _bucket(tracee_key(t), "tracee", i).tracee.append(t)
    return list(groups.values())


def cross_sensor_events(correlated: list[CorrelatedEvent]) -> list[CorrelatedEvent]:
    """The subset where both sensors fired (the de-duplicated, higher-confidence groups)."""
    return [c for c in correlated if c.cross_sensor]
