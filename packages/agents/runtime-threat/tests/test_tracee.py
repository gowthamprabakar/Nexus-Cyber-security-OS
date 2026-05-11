"""Tests for `runtime_threat.tools.tracee.tracee_alerts_read`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from runtime_threat.tools.tracee import TraceeAlert, TraceeError, tracee_alerts_read


def _tracee_alert(
    *,
    timestamp: int = 1715414400000000000,  # 2024-05-11 12:00:00 UTC in ns
    event_name: str = "security_file_open",
    process_name: str = "cat",
    process_id: int = 4242,
    host_name: str = "ip-10-0-1-42",
    container_image: str = "alpine:3.18",
    container_id: str = "abc123def456",
    args: list[dict[str, Any]] | None = None,
    severity: int = 3,
    description: str = "Read sensitive credential file",
    pod_name: str = "ssh-bastion-x",
    namespace: str = "kube-system",
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "eventName": event_name,
        "processName": process_name,
        "processId": process_id,
        "hostName": host_name,
        "containerImage": container_image,
        "containerId": container_id,
        "args": args if args is not None else [{"name": "pathname", "value": "/etc/shadow"}],
        "metadata": {"Severity": severity, "Description": description},
        "kubernetes": {"podName": pod_name, "namespace": namespace},
    }


def _write_jsonl(tmp_path: Path, payloads: list[dict[str, Any] | str]) -> Path:
    path = tmp_path / "tracee.jsonl"
    with path.open("w", encoding="utf-8") as h:
        for p in payloads:
            h.write(p + "\n" if isinstance(p, str) else json.dumps(p) + "\n")
    return path


# ---------------------------- happy path ---------------------------------


@pytest.mark.asyncio
async def test_reads_single_alert(tmp_path: Path) -> None:
    path = _write_jsonl(tmp_path, [_tracee_alert()])
    alerts = await tracee_alerts_read(feed_path=path)

    assert len(alerts) == 1
    assert isinstance(alerts[0], TraceeAlert)
    assert alerts[0].event_name == "security_file_open"
    assert alerts[0].severity == 3
    assert alerts[0].process_id == 4242
    # 1715414400_000_000_000 ns since epoch → 2024-05-11 08:00:00 UTC
    assert alerts[0].timestamp.tzinfo == UTC


@pytest.mark.asyncio
async def test_args_list_flattened_to_dict(tmp_path: Path) -> None:
    payload = _tracee_alert(
        args=[
            {"name": "pathname", "value": "/etc/shadow"},
            {"name": "flags", "value": "O_RDONLY"},
            {"name": "mode", "value": "0644"},
        ],
    )
    path = _write_jsonl(tmp_path, [payload])
    alerts = await tracee_alerts_read(feed_path=path)

    assert alerts[0].args == {
        "pathname": "/etc/shadow",
        "flags": "O_RDONLY",
        "mode": "0644",
    }


@pytest.mark.asyncio
async def test_kubernetes_metadata_lifted_to_top_level(tmp_path: Path) -> None:
    path = _write_jsonl(tmp_path, [_tracee_alert()])
    alerts = await tracee_alerts_read(feed_path=path)
    assert alerts[0].pod_name == "ssh-bastion-x"
    assert alerts[0].namespace == "kube-system"


@pytest.mark.asyncio
async def test_multiple_alerts(tmp_path: Path) -> None:
    payloads = [_tracee_alert(event_name=f"evt_{i}") for i in range(4)]
    path = _write_jsonl(tmp_path, list(payloads))
    alerts = await tracee_alerts_read(feed_path=path)
    assert {a.event_name for a in alerts} == {f"evt_{i}" for i in range(4)}


@pytest.mark.asyncio
async def test_empty_file_returns_empty_tuple(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    assert await tracee_alerts_read(feed_path=path) == ()


@pytest.mark.asyncio
async def test_accepts_iso_timestamp_for_forward_compat(tmp_path: Path) -> None:
    """Some Tracee builds emit ISO strings; tolerate them."""
    payload = _tracee_alert(timestamp=0)  # placeholder
    payload["timestamp"] = "2026-05-11T12:00:00Z"
    path = _write_jsonl(tmp_path, [payload])
    alerts = await tracee_alerts_read(feed_path=path)
    assert alerts[0].timestamp.year == 2026


# ---------------------------- malformed-line tolerance -------------------


@pytest.mark.asyncio
async def test_skips_malformed_json_line(tmp_path: Path) -> None:
    path = tmp_path / "feed.jsonl"
    with path.open("w") as h:
        h.write(json.dumps(_tracee_alert(event_name="good-1")) + "\n")
        h.write("{not valid json\n")
        h.write(json.dumps(_tracee_alert(event_name="good-2")) + "\n")

    alerts = await tracee_alerts_read(feed_path=path)
    assert {a.event_name for a in alerts} == {"good-1", "good-2"}


@pytest.mark.asyncio
async def test_skips_alerts_with_missing_required_fields(tmp_path: Path) -> None:
    """`timestamp` and `eventName` are required; partial alerts are dropped."""
    path = tmp_path / "feed.jsonl"
    with path.open("w") as h:
        h.write(json.dumps({"eventName": "no-time"}) + "\n")
        h.write(json.dumps({"timestamp": 1_000_000_000}) + "\n")
        h.write(json.dumps(_tracee_alert(event_name="valid")) + "\n")

    alerts = await tracee_alerts_read(feed_path=path)
    assert [a.event_name for a in alerts] == ["valid"]


@pytest.mark.asyncio
async def test_tolerates_missing_optional_subdicts(tmp_path: Path) -> None:
    """Tracee builds without container/k8s context should still parse."""
    bare = {
        "timestamp": 1715414400000000000,
        "eventName": "minimal",
        "processName": "p",
    }
    path = _write_jsonl(tmp_path, [bare])
    alerts = await tracee_alerts_read(feed_path=path)
    assert len(alerts) == 1
    assert alerts[0].args == {}
    assert alerts[0].severity == 0
    assert alerts[0].pod_name == ""
    assert alerts[0].container_id == ""


# ---------------------------- error path ---------------------------------


@pytest.mark.asyncio
async def test_missing_feed_raises_tracee_error(tmp_path: Path) -> None:
    with pytest.raises(TraceeError, match="tracee feed missing"):
        await tracee_alerts_read(feed_path=tmp_path / "does-not-exist.jsonl")


# ---------------------------- shape invariants ---------------------------


def test_tracee_alert_is_frozen() -> None:
    import dataclasses

    alert = TraceeAlert(
        timestamp=datetime.now(UTC),
        event_name="x",
        process_name="p",
        process_id=1,
        host_name="h",
        container_image="",
        container_id="",
    )
    assert dataclasses.is_dataclass(alert)
    with pytest.raises(dataclasses.FrozenInstanceError):
        alert.event_name = "mutated"  # type: ignore[misc]
