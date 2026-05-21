"""Tests — `supervisor.scheduled_queue` (Task 7).

10 tests covering the file-backed queue:

1.  Missing queue file -> drain returns empty list (no error).
2.  Single enqueue creates the file + drain returns the task.
3.  Drain clears the queue (second drain returns empty).
4.  Multiple enqueues preserve insertion order on drain.
5.  Duplicate task_id rejected by enqueue.
6.  Missing task_id rejected by enqueue.
7.  Malformed JSON file -> ScheduledQueueError on drain.
8.  Queue file containing non-array -> ScheduledQueueError.
9.  Empty customer_id rejected by queue_path.
10. ``peek`` returns tasks WITHOUT clearing the queue.

Persistence across "restart" is implicit — the queue is a file
on disk; both calls to ``drain`` after a fresh enqueue see the
same state regardless of process lifetime.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from supervisor.scheduled_queue import (
    ScheduledQueueError,
    drain,
    enqueue,
    peek,
    queue_path,
)


def test_missing_file_drain_returns_empty(tmp_path: Path) -> None:
    tasks = drain(tmp_path, customer_id="acme")
    assert tasks == []


def test_single_enqueue_drain_round_trip(tmp_path: Path) -> None:
    enqueue(
        tmp_path,
        customer_id="acme",
        task={"task_id": "t1", "target_agent": "cloud_posture"},
    )
    tasks = drain(tmp_path, customer_id="acme")
    assert len(tasks) == 1
    assert tasks[0].task_id == "t1"
    assert tasks[0].target_agent == "cloud_posture"
    assert tasks[0].customer_id == "acme"
    assert tasks[0].trigger_source.value == "scheduled_queue"


def test_drain_clears_the_queue(tmp_path: Path) -> None:
    enqueue(tmp_path, customer_id="acme", task={"task_id": "t1"})
    first = drain(tmp_path, customer_id="acme")
    assert len(first) == 1
    second = drain(tmp_path, customer_id="acme")
    assert second == []


def test_multiple_enqueues_preserve_order(tmp_path: Path) -> None:
    for i in range(3):
        enqueue(tmp_path, customer_id="acme", task={"task_id": f"t{i}"})
    tasks = drain(tmp_path, customer_id="acme")
    assert [t.task_id for t in tasks] == ["t0", "t1", "t2"]


def test_duplicate_task_id_rejected(tmp_path: Path) -> None:
    enqueue(tmp_path, customer_id="acme", task={"task_id": "t1"})
    with pytest.raises(ScheduledQueueError, match="already present"):
        enqueue(tmp_path, customer_id="acme", task={"task_id": "t1"})


def test_missing_task_id_rejected(tmp_path: Path) -> None:
    with pytest.raises(ScheduledQueueError, match=r"non-empty 'task_id'"):
        enqueue(tmp_path, customer_id="acme", task={"target_agent": "x"})


def test_malformed_json_raises(tmp_path: Path) -> None:
    path = queue_path(tmp_path, "acme")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not a json array", encoding="utf-8")
    with pytest.raises(ScheduledQueueError, match="malformed JSON"):
        drain(tmp_path, customer_id="acme")


def test_non_array_queue_file_raises(tmp_path: Path) -> None:
    path = queue_path(tmp_path, "acme")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"not": "an array"}', encoding="utf-8")
    with pytest.raises(ScheduledQueueError, match="must be a JSON array"):
        drain(tmp_path, customer_id="acme")


def test_empty_customer_id_rejected(tmp_path: Path) -> None:
    with pytest.raises(ScheduledQueueError, match="non-empty"):
        queue_path(tmp_path, "")


def test_peek_does_not_clear_the_queue(tmp_path: Path) -> None:
    enqueue(tmp_path, customer_id="acme", task={"task_id": "t1"})
    enqueue(tmp_path, customer_id="acme", task={"task_id": "t2"})

    first_peek = peek(tmp_path, customer_id="acme")
    assert [t.task_id for t in first_peek] == ["t1", "t2"]

    # Peek again — same tasks, queue still intact.
    second_peek = peek(tmp_path, customer_id="acme")
    assert [t.task_id for t in second_peek] == ["t1", "t2"]

    # Drain now — gets both tasks, then queue is empty.
    drained = drain(tmp_path, customer_id="acme")
    assert [t.task_id for t in drained] == ["t1", "t2"]
    assert drain(tmp_path, customer_id="acme") == []
