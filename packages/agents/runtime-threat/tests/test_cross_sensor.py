"""D.3 v0.2 Task 7 — Falco + Tracee cross-sensor correlation tests."""

from __future__ import annotations

from datetime import UTC, datetime

from runtime_threat.correlators.cross_sensor import (
    correlate_sensor_events,
    cross_sensor_events,
)
from runtime_threat.tools.falco_normalize import normalize_falco_event
from runtime_threat.tools.tracee_normalize import normalize_tracee_event

_RX = datetime(2026, 6, 10, tzinfo=UTC)


def _falco(cid: str, pid: str, rule: str = "R") -> object:
    return normalize_falco_event(
        {"rule": rule, "output_fields": {"container.id": cid, "proc.pid": pid}}, received_at=_RX
    )


def _tracee(cid: str, pid: int, name: str = "E") -> object:
    return normalize_tracee_event(
        {"eventName": name, "containerId": cid, "processId": pid}, received_at=_RX
    )


def test_same_container_and_pid_correlate_to_one_group() -> None:
    groups = correlate_sensor_events([_falco("c1", "100")], [_tracee("c1", 100)])
    assert len(groups) == 1
    assert groups[0].cross_sensor is True
    assert groups[0].event_count == 2  # de-dup: one group, both sensors


def test_different_containers_stay_separate() -> None:
    groups = correlate_sensor_events([_falco("c1", "100")], [_tracee("c2", 100)])
    assert len(groups) == 2
    assert all(not g.cross_sensor for g in groups)


def test_falco_only_group_not_cross_sensor() -> None:
    [g] = correlate_sensor_events([_falco("c1", "100")], [])
    assert g.falco and not g.tracee and g.cross_sensor is False


def test_tracee_only_group() -> None:
    [g] = correlate_sensor_events([], [_tracee("c1", 100)])
    assert g.tracee and not g.falco


def test_context_less_events_stay_singletons() -> None:
    # No container id and no pid → cannot correlate; each is its own group.
    groups = correlate_sensor_events([_falco("", ""), _falco("", "")], [])
    assert len(groups) == 2
    assert all(not g.cross_sensor for g in groups)


def test_cross_sensor_filter() -> None:
    groups = correlate_sensor_events(
        [_falco("c1", "100"), _falco("c2", "200")], [_tracee("c1", 100)]
    )
    cross = cross_sensor_events(groups)
    assert len(cross) == 1 and cross[0].key.container_id == "c1"


def test_empty_inputs() -> None:
    assert correlate_sensor_events([], []) == []


def test_multiple_events_same_key_accumulate() -> None:
    [g] = correlate_sensor_events(
        [_falco("c1", "100", "R1"), _falco("c1", "100", "R2")], [_tracee("c1", 100)]
    )
    assert len(g.falco) == 2 and len(g.tracee) == 1 and g.event_count == 3
