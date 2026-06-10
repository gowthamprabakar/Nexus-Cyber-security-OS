"""D.3 v0.2 Task 11 — passive behavioral baseline observer tests."""

from __future__ import annotations

from datetime import UTC, datetime

from runtime_threat.baseline.observer import BaselineObserver
from runtime_threat.tools.falco_normalize import normalize_falco_event
from runtime_threat.tools.tracee_normalize import normalize_tracee_event

_RX = datetime(2026, 6, 10, tzinfo=UTC)


def test_observe_process_accumulates_per_workload() -> None:
    obs = BaselineObserver()
    obs.observe_process("c1", "nginx")
    obs.observe_process("c1", "nginx")  # dedup
    obs.observe_process("c1", "sh")
    assert obs.baseline("c1").processes == {"nginx", "sh"}


def test_workloads_isolated() -> None:
    obs = BaselineObserver()
    obs.observe_process("c1", "nginx")
    obs.observe_process("c2", "redis")
    assert obs.baseline("c1").processes == {"nginx"}
    assert obs.baseline("c2").processes == {"redis"}
    assert set(obs.workloads()) == {"c1", "c2"}


def test_observe_connection_and_file() -> None:
    obs = BaselineObserver()
    obs.observe_connection("c1", "10.0.0.1:443")
    obs.observe_file("c1", "/etc/passwd")
    wb = obs.baseline("c1")
    assert wb.connections == {"10.0.0.1:443"} and wb.files == {"/etc/passwd"}


def test_empty_values_ignored() -> None:
    obs = BaselineObserver()
    obs.observe_process("", "x")
    obs.observe_process("c1", "")
    assert obs.workloads() == ()


def test_unknown_workload_returns_none() -> None:
    assert BaselineObserver().baseline("nope") is None


def test_observe_falco_extracts_process_and_file() -> None:
    obs = BaselineObserver()
    ev = normalize_falco_event(
        {
            "rule": "R",
            "output_fields": {"container.id": "c1", "proc.name": "bash", "fd.name": "/data/x"},
        },
        received_at=_RX,
    )
    obs.observe_falco(ev)
    wb = obs.baseline("c1")
    assert wb.processes == {"bash"} and wb.files == {"/data/x"}


def test_observe_tracee_extracts_process_and_pathname() -> None:
    obs = BaselineObserver()
    ev = normalize_tracee_event(
        {
            "eventName": "security_file_open",
            "containerId": "c1",
            "processName": "cat",
            "args": [{"name": "pathname", "value": "/etc/shadow"}],
        },
        received_at=_RX,
    )
    obs.observe_tracee(ev)
    wb = obs.baseline("c1")
    assert wb.processes == {"cat"} and wb.files == {"/etc/shadow"}


def test_observer_is_passive_no_drift_api() -> None:
    # Q5 / WI-R10: passive — the observer exposes no drift/detect surface at v0.2.
    obs = BaselineObserver()
    assert not hasattr(obs, "detect_drift")
    assert not hasattr(obs, "is_anomalous")
