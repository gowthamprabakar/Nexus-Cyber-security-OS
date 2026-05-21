"""File-backed scheduled-task queue — Stage 1 INGEST trigger source #3.

Per Q5: NO cron scheduler in v0.1. Operators enqueue tasks via
``supervisor schedule`` CLI (Task 13); the heartbeat loop drains
this file each tick.

**Storage layout:**
``<workspace_root>/.supervisor/scheduled/<customer_id>.json`` — a
JSON array of task dicts. The file is created on first enqueue;
missing file is treated as an empty queue (not an error).

**Concurrency:**
- ``enqueue(...)`` and ``drain(...)`` BOTH acquire ``fcntl.flock``
  on the queue file for the duration of the read-modify-write.
  The same per-customer lock the heartbeat loop uses (Task 10)
  protects the queue from concurrent appends.
- ``drain(...)`` is atomic via the read-then-rewrite pattern:
  read the whole file, return its contents, write back an empty
  array. The fcntl-lock holds across the whole sequence.

**File format**:

```json
[
  {
    "task_id": "...",
    "customer_id": "...",
    "target_agent": "...",
    "task_type": "...",
    "delta_type": "...",
    "description": "...",
    "priority": 0,
    "scheduled_at": "2026-05-21T12:00:00+00:00"
  },
  ...
]
```

Read-only contract preserved: the queue file is the only state
this module touches. No agent NLAH directory writes. No fabric.
"""

from __future__ import annotations

import fcntl
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from supervisor.schemas import IncomingTask, TriggerSource

_SCHEDULED_SUBDIR = Path(".supervisor") / "scheduled"


class ScheduledQueueError(ValueError):
    """Raised when the scheduled-queue file violates the storage contract."""


def queue_path(workspace_root: Path, customer_id: str) -> Path:
    """Return the canonical queue-file path for a customer."""
    if not customer_id:
        raise ScheduledQueueError("customer_id must be a non-empty string")
    return workspace_root / _SCHEDULED_SUBDIR / f"{customer_id}.json"


def enqueue(
    workspace_root: Path,
    *,
    customer_id: str,
    task: dict[str, Any],
) -> None:
    """Append one task dict to the customer's scheduled-task queue.

    The task dict must carry at least ``task_id``; other fields
    are optional and propagate to the materialised ``IncomingTask``
    on drain. ``scheduled_at`` is stamped automatically if absent.

    Raises:
        ScheduledQueueError: when ``task_id`` is missing or
            ``task_id`` collides with an existing queued task.
    """
    if "task_id" not in task or not task["task_id"]:
        raise ScheduledQueueError("task dict must carry a non-empty 'task_id'")

    path = queue_path(workspace_root, customer_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    with _locked_open(path, mode="a+") as fh:
        fh.seek(0)
        raw = fh.read()
        existing = _parse_array(raw, path)

        if any(entry.get("task_id") == task["task_id"] for entry in existing):
            raise ScheduledQueueError(f"task_id={task['task_id']!r} already present in {path}")

        payload = dict(task)
        payload.setdefault("scheduled_at", datetime.now(UTC).isoformat())
        existing.append(payload)

        fh.seek(0)
        fh.truncate(0)
        fh.write(json.dumps(existing, separators=(",", ":")))


def drain(
    workspace_root: Path,
    *,
    customer_id: str,
) -> list[IncomingTask]:
    """Return every queued task + clear the queue.

    Missing file -> empty list (not an error). Per Q5 v0.1: drain
    is atomic under the fcntl lock; the heartbeat loop calls this
    once per tick.

    Each entry materialises to an ``IncomingTask`` with
    ``trigger_source=SCHEDULED_QUEUE`` and ``received_at`` =
    drain time (or the entry's ``scheduled_at`` if present).
    """
    path = queue_path(workspace_root, customer_id)
    if not path.is_file():
        return []

    now = datetime.now(UTC)
    with _locked_open(path, mode="r+") as fh:
        fh.seek(0)
        raw = fh.read()
        entries = _parse_array(raw, path)
        fh.seek(0)
        fh.truncate(0)
        fh.write("[]")

    return [_materialize(entry, customer_id=customer_id, now=now) for entry in entries]


def peek(
    workspace_root: Path,
    *,
    customer_id: str,
) -> list[IncomingTask]:
    """Return queued tasks WITHOUT clearing the queue (test/CLI utility)."""
    path = queue_path(workspace_root, customer_id)
    if not path.is_file():
        return []
    now = datetime.now(UTC)
    raw = path.read_text(encoding="utf-8")
    entries = _parse_array(raw, path)
    return [_materialize(entry, customer_id=customer_id, now=now) for entry in entries]


def _locked_open(path: Path, *, mode: str) -> Any:
    """Open ``path`` and acquire ``fcntl.LOCK_EX`` until close."""
    fh = path.open(mode, encoding="utf-8")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    return fh


def _parse_array(raw: str, path: Path) -> list[dict[str, Any]]:
    if not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ScheduledQueueError(f"{path}: malformed JSON: {exc}") from exc
    if not isinstance(parsed, list):
        raise ScheduledQueueError(
            f"{path}: queue file must be a JSON array; got {type(parsed).__name__}"
        )
    typed: list[dict[str, Any]] = []
    for i, entry in enumerate(parsed):
        if not isinstance(entry, dict):
            raise ScheduledQueueError(
                f"{path}: entries[{i}] must be a mapping; got {type(entry).__name__}"
            )
        typed.append(entry)
    return typed


def _materialize(
    entry: dict[str, Any],
    *,
    customer_id: str,
    now: datetime,
) -> IncomingTask:
    received_at_raw = entry.get("scheduled_at")
    received_at: datetime
    if isinstance(received_at_raw, str):
        try:
            received_at = datetime.fromisoformat(received_at_raw)
        except ValueError:
            received_at = now
    else:
        received_at = now

    return IncomingTask(
        task_id=str(entry["task_id"]),
        customer_id=str(entry.get("customer_id", customer_id)),
        trigger_source=TriggerSource.SCHEDULED_QUEUE,
        target_agent=_optional_str(entry.get("target_agent")),
        task_type=_optional_str(entry.get("task_type")),
        delta_type=_optional_str(entry.get("delta_type")),
        description=str(entry.get("description", "")),
        priority=int(entry.get("priority", 0)),
        received_at=received_at,
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


__all__ = [
    "ScheduledQueueError",
    "drain",
    "enqueue",
    "peek",
    "queue_path",
]
