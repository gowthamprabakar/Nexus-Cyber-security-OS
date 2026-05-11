"""Tracee alerts JSONL reader.

Tracee's JSON output emits one alert per line. Schema differs enough
from Falco's that it warrants its own normalizer:

    {
      "timestamp": 1715414400000000000,
      "eventName": "security_file_open",
      "processName": "cat",
      "processId": 4242,
      "hostName": "ip-10-0-1-42",
      "containerImage": "alpine:3.18",
      "containerId": "abc123",
      "args": [
        {"name": "pathname", "value": "/etc/shadow"},
        {"name": "flags", "value": "O_RDONLY"}
      ],
      "metadata": {
        "Severity": 3,
        "Description": "Read sensitive credential file"
      },
      "kubernetes": {
        "podName": "ssh-bastion-x",
        "namespace": "kube-system"
      }
    }

Key deltas vs. Falco:

- Timestamp is **nanoseconds since epoch** (int), not RFC3339 string.
- `args` is a list of `{name, value}` dicts — we flatten to a dict.
- Severity is an int 0-3 inside `metadata.Severity` (vs. Falco's
  Emergency/Alert/.../Debug priority string).
- Kubernetes info is its own sub-dict.

Per ADR-005 the read goes through `asyncio.to_thread` (filesystem read is
sync). Malformed lines are silently skipped (same convention as the Falco
reader). Live Tracee streaming is deferred to Phase 1c.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class TraceeError(RuntimeError):
    """Tracee feed could not be read."""


@dataclass(frozen=True, slots=True)
class TraceeAlert:
    """One Tracee alert, parsed from a single JSONL line."""

    timestamp: datetime
    event_name: str
    process_name: str
    process_id: int
    host_name: str
    container_image: str
    container_id: str
    args: dict[str, str] = field(default_factory=dict)
    severity: int = 0  # Tracee's 0-3 scale; mapped to OCSF in Task 6
    description: str = ""
    pod_name: str = ""
    namespace: str = ""


async def tracee_alerts_read(
    *,
    feed_path: Path | str,
    timeout_sec: float = 60.0,
) -> tuple[TraceeAlert, ...]:
    """Read a Tracee JSONL feed and return every successfully parsed alert.

    Args:
        feed_path: Path to a Tracee JSONL feed.
        timeout_sec: Wall-clock timeout — raises if the read runs long.

    Raises:
        TraceeError: when the feed file is missing or the read exceeds
            `timeout_sec`. Malformed JSON lines are silently skipped.
    """
    path = Path(feed_path)
    if not path.is_file():
        raise TraceeError(f"tracee feed missing: {path}")

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_read_feed_sync, path),
            timeout=timeout_sec,
        )
    except TimeoutError as exc:
        raise TraceeError(f"tracee_alerts_read timed out after {timeout_sec}s") from exc


def _read_feed_sync(path: Path) -> tuple[TraceeAlert, ...]:
    out: list[TraceeAlert] = []
    with path.open("r", encoding="utf-8") as handle:
        for alert in _parse_lines(handle):
            out.append(alert)
    return tuple(out)


def _parse_lines(handle: Iterator[str]) -> Iterator[TraceeAlert]:
    for raw in handle:
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue

        timestamp = _parse_timestamp(obj.get("timestamp"))
        if timestamp is None:
            continue
        event_name = obj.get("eventName")
        if not isinstance(event_name, str) or not event_name:
            continue

        args_flat = _flatten_args(obj.get("args"))
        metadata = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
        severity_raw = metadata.get("Severity", 0) if metadata else 0
        severity = int(severity_raw) if isinstance(severity_raw, (int, float)) else 0
        description = (
            str(metadata.get("Description", ""))
            if metadata and isinstance(metadata.get("Description"), str)
            else ""
        )

        k8s = obj.get("kubernetes") if isinstance(obj.get("kubernetes"), dict) else {}
        pod_name = str(k8s.get("podName", "")) if k8s else ""
        namespace = str(k8s.get("namespace", "")) if k8s else ""

        yield TraceeAlert(
            timestamp=timestamp,
            event_name=event_name,
            process_name=str(obj.get("processName", "")),
            process_id=_safe_int(obj.get("processId", 0)),
            host_name=str(obj.get("hostName", "")),
            container_image=str(obj.get("containerImage", "")),
            container_id=str(obj.get("containerId", "")),
            args=args_flat,
            severity=severity,
            description=description,
            pod_name=pod_name,
            namespace=namespace,
        )


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse Tracee's nanoseconds-since-epoch timestamp.

    Tolerates ISO strings too (some Tracee builds emit them) for forward
    compatibility.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        # nanoseconds → seconds
        return datetime.fromtimestamp(value / 1_000_000_000, tz=UTC)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _flatten_args(value: Any) -> dict[str, str]:
    """`[{name, value}, ...]` → `{name: value, ...}`. Skips malformed entries."""
    if not isinstance(value, list):
        return {}
    out: dict[str, str] = {}
    for entry in value:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        val = entry.get("value")
        if isinstance(name, str) and name:
            out[name] = str(val) if val is not None else ""
    return out


def _safe_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


__all__ = ["TraceeAlert", "TraceeError", "tracee_alerts_read"]
