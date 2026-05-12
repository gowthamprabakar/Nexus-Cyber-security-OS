"""`audit_jsonl_read` — filesystem ingest for `charter.audit.AuditLog` files.

Reads an `audit.jsonl` file produced by `charter.audit.AuditLog` and
converts each entry into the F.6 `AuditEvent` wire shape. Per ADR-005
the filesystem read happens in `asyncio.to_thread` (the underlying
file I/O is sync); the wrapper is `async` to fit the agent driver's
TaskGroup fan-out (F.6 Task 12).

The reader is **forgiving**: a single malformed line — bad JSON,
missing fields, hash that fails AuditEvent validation — is dropped
silently rather than aborting the whole ingest. Operational reality:
audit logs occasionally interleave noise (rotated tail, partial
flush during a crash) and a strict reader would jam compliance
exports on a single bad byte.

`AuditEntry.run_id` is promoted to `AuditEvent.correlation_id` — same
concept, different name across the two surfaces. Tenant is stamped
from the caller-supplied argument because `charter.audit.AuditLog`
doesn't carry tenant in v0.1 (it's a per-run-process log; tenant is
implicit from which process wrote it).
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from audit.schemas import AuditEvent


class AuditJsonlError(RuntimeError):
    """The `audit.jsonl` feed could not be read."""


async def audit_jsonl_read(
    *,
    path: Path,
    tenant_id: str,
) -> tuple[AuditEvent, ...]:
    """Read an `audit.jsonl` file and return the parsed events.

    The reader runs the filesystem read on a worker thread (`asyncio.
    to_thread`) so the agent driver can fan it out alongside other
    ingest tools via `asyncio.TaskGroup`.
    """
    return await asyncio.to_thread(_read_sync, path, tenant_id)


def _read_sync(path: Path, tenant_id: str) -> tuple[AuditEvent, ...]:
    if not path.exists():
        raise AuditJsonlError(f"audit.jsonl not found: {path}")
    if not path.is_file():
        raise AuditJsonlError(f"audit.jsonl is not a file: {path}")

    source = f"jsonl:{path}"
    events: list[AuditEvent] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            event = _try_parse_line(stripped, tenant_id=tenant_id, source=source)
            if event is not None:
                events.append(event)
    return tuple(events)


def _try_parse_line(
    raw: str,
    *,
    tenant_id: str,
    source: str,
) -> AuditEvent | None:
    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None

    timestamp = _parse_timestamp(record.get("timestamp"))
    if timestamp is None:
        return None

    try:
        return AuditEvent(
            tenant_id=tenant_id,
            correlation_id=str(record.get("run_id", "")),
            agent_id=str(record.get("agent", "")),
            action=str(record.get("action", "")),
            payload=dict(record.get("payload", {}) or {}),
            previous_hash=str(record.get("previous_hash", "")),
            entry_hash=str(record.get("entry_hash", "")),
            emitted_at=timestamp,
            source=source,
        )
    except ValidationError:
        return None


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


__all__ = ["AuditJsonlError", "audit_jsonl_read"]
