"""Tracee live event normalization + syscall enrichment (D.3 v0.2 Task 6).

Turns a raw Tracee event dict into the same `TraceeAlert` the offline path produces
(mirroring its field extraction, so downstream stays byte-identical), plus a
**syscall context** pulled from the event name + args. The receive timestamp is
**caller-provided** (`received_at`) so the normalizer stays deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from runtime_threat.tools.tracee import (
    TraceeAlert,
    _flatten_args,
    _parse_timestamp,
    _safe_int,
)


@dataclass(frozen=True, slots=True)
class SyscallContext:
    syscall: str = ""
    pathname: str = ""
    flags: str = ""
    return_value: str = ""


@dataclass(frozen=True, slots=True)
class NormalizedTraceeEvent:
    alert: TraceeAlert
    syscall: SyscallContext


def extract_syscall_context(alert: TraceeAlert) -> SyscallContext:
    """Pull the syscall name + key args (pathname / flags / return value) from an alert."""
    a = alert.args
    return SyscallContext(
        syscall=alert.event_name,
        pathname=a.get("pathname", ""),
        flags=a.get("flags", ""),
        return_value=a.get("returnValue", ""),
    )


def normalize_tracee_event(
    raw: dict[str, Any], *, received_at: datetime
) -> NormalizedTraceeEvent | None:
    """Normalize a raw Tracee event → `(TraceeAlert, SyscallContext)`. Returns `None` if
    the event has no `eventName`. ``received_at`` is used when the event carries no own
    timestamp."""
    event_name = raw.get("eventName")
    if not isinstance(event_name, str) or not event_name:
        return None

    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    severity_raw = metadata.get("Severity", 0) if metadata else 0
    severity = int(severity_raw) if isinstance(severity_raw, (int, float)) else 0
    description = (
        str(metadata.get("Description", ""))
        if metadata and isinstance(metadata.get("Description"), str)
        else ""
    )
    k8s = raw.get("kubernetes") if isinstance(raw.get("kubernetes"), dict) else {}

    alert = TraceeAlert(
        timestamp=_parse_timestamp(raw.get("timestamp")) or received_at,
        event_name=event_name,
        process_name=str(raw.get("processName", "")),
        process_id=_safe_int(raw.get("processId", 0)),
        host_name=str(raw.get("hostName", "")),
        container_image=str(raw.get("containerImage", "")),
        container_id=str(raw.get("containerId", "")),
        args=_flatten_args(raw.get("args")),
        severity=severity,
        description=description,
        pod_name=str(k8s.get("podName", "")) if k8s else "",
        namespace=str(k8s.get("namespace", "")) if k8s else "",
    )
    return NormalizedTraceeEvent(alert=alert, syscall=extract_syscall_context(alert))
