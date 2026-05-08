"""Workspace manager — path-addressable storage for agent invocations."""

from __future__ import annotations

from pathlib import Path

_MEMORY_KINDS = ("episodic", "procedural", "semantic")


class WorkspaceManager:
    """Owns the per-invocation workspace and persistent memory mount points."""

    def __init__(self, workspace: Path, persistent_root: Path) -> None:
        self.workspace = Path(workspace)
        self.persistent_root = Path(persistent_root)
        self._bytes_written = 0

    def setup(self) -> None:
        """Create workspace + persistent memory subdirectories."""
        self.workspace.mkdir(parents=True, exist_ok=True)
        for kind in _MEMORY_KINDS:
            (self.persistent_root / kind).mkdir(parents=True, exist_ok=True)

    def write_output(self, name: str, data: bytes) -> Path:
        """Write a required output to the workspace."""
        if "/" in name or ".." in name:
            raise ValueError(f"output name must be a flat filename, got {name!r}")
        target = self.workspace / name
        target.write_bytes(data)
        self._bytes_written += len(data)
        return target

    def missing_outputs(self, required: list[str]) -> list[str]:
        return [name for name in required if not (self.workspace / name).exists()]

    def bytes_written(self) -> int:
        return self._bytes_written

    def episodic(self) -> Path:
        return self.persistent_root / "episodic"

    def procedural(self) -> Path:
        return self.persistent_root / "procedural"

    def semantic(self) -> Path:
        return self.persistent_root / "semantic"
