"""Snapshot artifact handling (D.3 v0.2 Task 14).

Stores the captured forensic-snapshot payload to the filesystem with an **audit-chain
reference**, and exposes **read-only** access for the downstream Investigation agent.
Artifacts are write-once: the store has no update/delete surface — captured evidence is
immutable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from runtime_threat.actions.snapshot import SnapshotAction


@dataclass(frozen=True, slots=True)
class SnapshotArtifact:
    snapshot_id: str
    host_id: str
    container_id: str
    artifact_path: str
    audit_ref: str
    created_at: str  # ISO 8601


class SnapshotArtifactStore:
    """A write-once, read-only artifact store rooted at a directory. Each snapshot gets a
    ``<id>.data`` payload file + a ``<id>.json`` metadata file."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)

    def _data_path(self, snapshot_id: str) -> Path:
        return self._root / f"{snapshot_id}.data"

    def _meta_path(self, snapshot_id: str) -> Path:
        return self._root / f"{snapshot_id}.json"

    def store(
        self,
        action: SnapshotAction,
        *,
        snapshot_id: str,
        audit_ref: str,
        data: str,
        created_at: datetime,
    ) -> SnapshotArtifact:
        """Persist the snapshot payload + metadata; returns the artifact reference."""
        self._root.mkdir(parents=True, exist_ok=True)
        self._data_path(snapshot_id).write_text(data, encoding="utf-8")
        artifact = SnapshotArtifact(
            snapshot_id=snapshot_id,
            host_id=action.host_id,
            container_id=action.container_id,
            artifact_path=str(self._data_path(snapshot_id)),
            audit_ref=audit_ref,
            created_at=created_at.isoformat(),
        )
        self._meta_path(snapshot_id).write_text(
            json.dumps(
                {
                    "snapshot_id": artifact.snapshot_id,
                    "host_id": artifact.host_id,
                    "container_id": artifact.container_id,
                    "artifact_path": artifact.artifact_path,
                    "audit_ref": artifact.audit_ref,
                    "created_at": artifact.created_at,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return artifact

    def load(self, snapshot_id: str) -> SnapshotArtifact | None:
        """Read-only metadata access (for the Investigation agent). `None` if absent."""
        meta = self._meta_path(snapshot_id)
        if not meta.is_file():
            return None
        d = json.loads(meta.read_text(encoding="utf-8"))
        return SnapshotArtifact(
            snapshot_id=d["snapshot_id"],
            host_id=d.get("host_id", ""),
            container_id=d.get("container_id", ""),
            artifact_path=d.get("artifact_path", ""),
            audit_ref=d.get("audit_ref", ""),
            created_at=d.get("created_at", ""),
        )

    def read_data(self, snapshot_id: str) -> str | None:
        """Read-only access to the captured payload. `None` if absent."""
        path = self._data_path(snapshot_id)
        return path.read_text(encoding="utf-8") if path.is_file() else None

    def list_artifacts(self) -> tuple[str, ...]:
        if not self._root.is_dir():
            return ()
        return tuple(sorted(p.stem for p in self._root.glob("*.json")))
