"""SQLite-backed scheduled queue with WAL durability (supervisor v0.2 Task 11, Q5).

Replaces the v0.1 JSON-array queue with a **SQLite** store in **WAL** mode, so an enqueue
survives a crash between writes (the JSON-array rewrite could lose the file on a mid-write
crash). FIFO order is by an autoincrement ``seq``; ``(customer_id, task_id)`` is unique
(re-enqueueing a live task id is rejected, matching v0.1). ``import_tasks`` backfills the
existing JSON-array queue on first v0.2 boot (backward compat). Postgres via F.5 is v0.3.

This is plain persistence the supervisor owns — not a charter-gated tool (the deviation holds,
WI-O11).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE(customer_id, task_id)
)
"""


class SqliteQueueError(ValueError):
    """A scheduled-queue operation failed (e.g. a duplicate task id)."""


class SqliteQueueStore:
    """A durable scheduled-task queue backed by a SQLite database in WAL mode."""

    def __init__(self, db_path: Path) -> None:
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    @property
    def journal_mode(self) -> str:
        row = self._conn.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]).lower()

    def enqueue(self, *, customer_id: str, task: dict[str, Any]) -> None:
        """Append one task. Raises ``SqliteQueueError`` on a missing or duplicate ``task_id``."""
        task_id = task.get("task_id")
        if not task_id:
            raise SqliteQueueError("task dict must carry a non-empty 'task_id'")
        try:
            self._conn.execute(
                "INSERT INTO scheduled_tasks (customer_id, task_id, payload) VALUES (?, ?, ?)",
                (customer_id, str(task_id), json.dumps(task)),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            raise SqliteQueueError(
                f"task_id={task_id!r} already present for customer {customer_id!r}"
            ) from exc

    def peek(self, *, customer_id: str) -> list[dict[str, Any]]:
        """All queued tasks for ``customer_id`` in FIFO order (non-destructive)."""
        rows = self._conn.execute(
            "SELECT payload FROM scheduled_tasks WHERE customer_id = ? ORDER BY seq",
            (customer_id,),
        ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def drain(self, *, customer_id: str) -> list[dict[str, Any]]:
        """Return all queued tasks for ``customer_id`` and remove them, atomically."""
        cur = self._conn.execute("BEGIN")
        try:
            rows = cur.execute(
                "SELECT payload FROM scheduled_tasks WHERE customer_id = ? ORDER BY seq",
                (customer_id,),
            ).fetchall()
            cur.execute("DELETE FROM scheduled_tasks WHERE customer_id = ?", (customer_id,))
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return [json.loads(r[0]) for r in rows]

    def import_tasks(self, tasks: Sequence[dict[str, Any]], *, customer_id: str) -> int:
        """Backfill tasks (e.g. from the v0.1 JSON-array file); duplicates are skipped. Returns
        the number imported."""
        imported = 0
        for task in tasks:
            try:
                self.enqueue(customer_id=customer_id, task=task)
                imported += 1
            except SqliteQueueError:
                continue
        return imported

    def close(self) -> None:
        self._conn.close()
