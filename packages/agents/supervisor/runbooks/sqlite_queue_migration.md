# Runbook — SQLite Queue Migration from JSONL (supervisor v0.2)

## What changed (Q5)

The scheduled queue moved from the v0.1 JSON-array file to a **SQLite** store in **WAL** mode
(`queue/sqlite_store.py`) — durable across a crash between writes.

## Migrate existing tasks

On first v0.2 boot, read the v0.1 queue file and backfill:

```python
store = SqliteQueueStore(db_path)
store.import_tasks(existing_tasks, customer_id=cid)  # duplicates skipped
```

## Draining + crash recovery

`queue/drainer.py::QueueDrainer.drain` runs claim -> process -> complete per task. If the
process crashes mid-task, the claimed task is **re-dequeued** on the next drain — nothing lost.
A drained queue emits `supervisor.queue.drained`. Postgres via F.5 is v0.3.
