"""Behavioral baseline persistence (D.3 v0.2 Task 12).

Persists per-customer workload baselines to JSON so the passive observations (Task 11)
survive across runs. Per **Q5** the stored data is what v0.3 active drift detection will
read; v0.2 only writes + reads it (no detection).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from runtime_threat.baseline.observer import WorkloadBaseline


def _serialize(wb: WorkloadBaseline) -> dict[str, list[str]]:
    # Sets → sorted lists for stable, JSON-serializable, diff-friendly output.
    return {
        "processes": sorted(wb.processes),
        "connections": sorted(wb.connections),
        "files": sorted(wb.files),
    }


def _deserialize(workload_id: str, data: dict[str, Any]) -> WorkloadBaseline:
    return WorkloadBaseline(
        workload_id=workload_id,
        processes=set(data.get("processes", [])),
        connections=set(data.get("connections", [])),
        files=set(data.get("files", [])),
    )


class BaselineStore:
    """A per-customer JSON-file baseline store rooted at a directory."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)

    def _path(self, customer_id: str) -> Path:
        return self._root / f"{customer_id}.json"

    def exists(self, customer_id: str) -> bool:
        return self._path(customer_id).is_file()

    def save(self, customer_id: str, baselines: Iterable[WorkloadBaseline]) -> Path:
        """Persist a customer's workload baselines; returns the file path."""
        payload = {
            "customer_id": customer_id,
            "workloads": {wb.workload_id: _serialize(wb) for wb in baselines},
        }
        self._root.mkdir(parents=True, exist_ok=True)
        path = self._path(customer_id)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def load(self, customer_id: str) -> dict[str, WorkloadBaseline]:
        """Load a customer's workload baselines; `{}` if none stored."""
        path = self._path(customer_id)
        if not path.is_file():
            return {}
        blob = json.loads(path.read_text(encoding="utf-8"))
        workloads = blob.get("workloads", {})
        return {
            wl: _deserialize(wl, data) for wl, data in workloads.items() if isinstance(data, dict)
        }
