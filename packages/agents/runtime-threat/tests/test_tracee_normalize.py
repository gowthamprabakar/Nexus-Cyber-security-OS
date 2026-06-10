"""D.3 v0.2 Task 6 — Tracee live event normalization + syscall enrichment tests."""

from __future__ import annotations

from datetime import UTC, datetime

from runtime_threat.tools.tracee_normalize import (
    extract_syscall_context,
    normalize_tracee_event,
)

_RX = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)

_RAW = {
    "timestamp": 1_700_000_000_000_000_000,
    "eventName": "security_file_open",
    "processName": "cat",
    "processId": 4242,
    "hostName": "node-1",
    "containerImage": "evil/img",
    "containerId": "c0ffee",
    "args": [
        {"name": "pathname", "value": "/etc/shadow"},
        {"name": "flags", "value": "O_RDONLY"},
        {"name": "returnValue", "value": "0"},
    ],
    "metadata": {"Severity": 3, "Description": "sensitive file read"},
    "kubernetes": {"podName": "db-0", "namespace": "prod"},
}


def test_normalize_full_event_mirrors_offline_fields() -> None:
    norm = normalize_tracee_event(_RAW, received_at=_RX)
    assert norm is not None
    a = norm.alert
    assert a.event_name == "security_file_open" and a.process_name == "cat"
    assert a.process_id == 4242 and a.host_name == "node-1"
    assert a.container_image == "evil/img" and a.container_id == "c0ffee"
    assert a.severity == 3 and a.description == "sensitive file read"
    assert a.pod_name == "db-0" and a.namespace == "prod"


def test_syscall_context() -> None:
    s = normalize_tracee_event(_RAW, received_at=_RX).syscall
    assert s.syscall == "security_file_open"
    assert s.pathname == "/etc/shadow" and s.flags == "O_RDONLY" and s.return_value == "0"


def test_missing_event_name_returns_none() -> None:
    assert normalize_tracee_event({"timestamp": 1}, received_at=_RX) is None


def test_missing_timestamp_uses_received_at() -> None:
    norm = normalize_tracee_event({"eventName": "x"}, received_at=_RX)
    assert norm is not None and norm.alert.timestamp == _RX


def test_empty_args_empty_syscall_paths() -> None:
    norm = normalize_tracee_event({"eventName": "x"}, received_at=_RX)
    assert norm.syscall.syscall == "x" and norm.syscall.pathname == ""


def test_extract_syscall_standalone() -> None:
    norm = normalize_tracee_event(_RAW, received_at=_RX)
    assert extract_syscall_context(norm.alert).pathname == "/etc/shadow"


def test_nanosecond_timestamp_parsed() -> None:
    norm = normalize_tracee_event(_RAW, received_at=_RX)
    assert norm.alert.timestamp.year == 2023  # 1.7e18 ns ≈ 2023-11-14
