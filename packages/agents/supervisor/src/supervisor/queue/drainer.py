"""Queue drainer with SQLite transactions + crash recovery (supervisor v0.2 Task 12, Q5).

Drains the SQLite scheduled queue with a **claim -> process -> complete** cycle, each step a
SQLite transaction, so a crash between claim and complete loses nothing: a claimed-but-not-
completed task stays in the DB and is **re-dequeued** on the next ``drain`` (crash recovery).
The ``process`` callback is where the supervisor dispatches the delegation + emits the F.6
audit entry; the drainer only sequences the durable bookkeeping.

It opens its own connection (WAL allows concurrent readers/writers) and adds a ``claimed``
column to the Task-11 table if absent — additive, no schema rewrite.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class ClaimedTask:
    seq: int
    task: dict[str, Any]


@dataclass(frozen=True, slots=True)
class DrainSummary:
    drained: int
    recovered: int


class QueueDrainer:
    """Transactional drainer over the Task-11 SQLite queue with crash recovery."""

    def __init__(self, db_path: Path) -> None:
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._ensure_claimed_column()

    def _ensure_claimed_column(self) -> None:
        tables = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scheduled_tasks'"
        ).fetchone()
        if tables is None:
            return
        columns = [
            r[1] for r in self._conn.execute("PRAGMA table_info(scheduled_tasks)").fetchall()
        ]
        if "claimed" not in columns:
            self._conn.execute(
                "ALTER TABLE scheduled_tasks ADD COLUMN claimed INTEGER NOT NULL DEFAULT 0"
            )
            self._conn.commit()

    def claim_next(self, *, customer_id: str) -> ClaimedTask | None:
        """Atomically claim the oldest unclaimed task (mark it in-progress, don't delete)."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT seq, payload FROM scheduled_tasks "
                "WHERE customer_id = ? AND claimed = 0 ORDER BY seq LIMIT 1",
                (customer_id,),
            ).fetchone()
            if row is None:
                self._conn.commit()
                return None
            seq, payload = row
            self._conn.execute("UPDATE scheduled_tasks SET claimed = 1 WHERE seq = ?", (seq,))
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return ClaimedTask(seq=int(seq), task=json.loads(payload))

    def complete(self, seq: int) -> None:
        """Delete a successfully-processed task."""
        self._conn.execute("DELETE FROM scheduled_tasks WHERE seq = ?", (seq,))
        self._conn.commit()

    def recover_claimed(self, *, customer_id: str) -> int:
        """Reset any claimed-but-not-completed tasks back to unclaimed (re-dequeue after a
        crash). Returns how many were recovered."""
        cur = self._conn.execute(
            "UPDATE scheduled_tasks SET claimed = 0 WHERE customer_id = ? AND claimed = 1",
            (customer_id,),
        )
        self._conn.commit()
        return cur.rowcount

    async def drain(
        self,
        *,
        customer_id: str,
        process: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> DrainSummary:
        """Recover any stale claims, then claim -> process -> complete each due task in order.
        If ``process`` raises, the claimed task is left for the next drain to recover."""
        recovered = self.recover_claimed(customer_id=customer_id)
        drained = 0
        while True:
            claimed = self.claim_next(customer_id=customer_id)
            if claimed is None:
                break
            await process(claimed.task)
            self.complete(claimed.seq)
            drained += 1
        return DrainSummary(drained=drained, recovered=recovered)

    def close(self) -> None:
        self._conn.close()
