"""Multi-cloud background scan scheduler (data-security v0.2 Task 16).

Per **WI-S11** this is continuous-monitoring **INFRASTRUCTURE only** — it decides WHEN each
cloud source (AWS S3 / Azure Blob / GCS) is due for a re-scan, deterministically
(caller-provided ``now``), with independent per-source intervals. It does **not** run scans
and is **not** wired into ``agent.run()``; driving the production loop is the **Phase C**
consolidated retrofit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


class CloudSource(StrEnum):
    AWS_S3 = "aws_s3"
    AZURE_BLOB = "azure_blob"
    GCS = "gcs"


@dataclass(slots=True)
class SourceSchedule:
    source: CloudSource
    interval_seconds: int
    last_run_at: datetime | None = None


class ScanScheduler:
    """Tracks per-source scan intervals + computes which sources are due."""

    def __init__(self) -> None:
        self._schedules: dict[CloudSource, SourceSchedule] = {}

    def register(self, source: CloudSource, *, interval_seconds: int) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._schedules[source] = SourceSchedule(source, interval_seconds)

    def sources(self) -> tuple[CloudSource, ...]:
        return tuple(self._schedules)

    def mark_ran(self, source: CloudSource, *, at: datetime) -> None:
        sched = self._schedules.get(source)
        if sched is None:
            raise KeyError(f"source {source!r} is not registered")
        sched.last_run_at = at

    def next_due_at(self, source: CloudSource) -> datetime | None:
        sched = self._schedules[source]
        if sched.last_run_at is None:
            return None
        return sched.last_run_at + timedelta(seconds=sched.interval_seconds)

    def due(self, now: datetime) -> list[CloudSource]:
        """The sources due for a scan at ``now`` — never-run ones are always due."""
        out: list[CloudSource] = []
        for source, sched in self._schedules.items():
            if sched.last_run_at is None or now >= sched.last_run_at + timedelta(
                seconds=sched.interval_seconds
            ):
                out.append(source)
        return out
