"""Append-only hash-chained audit log."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    timestamp: str
    agent: str
    run_id: str
    action: str
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(raw: str) -> AuditEntry:
        return AuditEntry(**json.loads(raw))


def _hash_entry(
    timestamp: str,
    agent: str,
    run_id: str,
    action: str,
    payload: dict[str, Any],
    previous_hash: str,
) -> str:
    canonical = json.dumps(
        {
            "timestamp": timestamp,
            "agent": agent,
            "run_id": run_id,
            "action": action,
            "payload": payload,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only hash chain. One file per run.

    The first entry's previous_hash is the genesis (64 zeroes). Every
    subsequent entry's previous_hash is the previous entry's entry_hash.
    """

    def __init__(self, path: Path, agent: str, run_id: str) -> None:
        self.path = Path(path)
        self.agent = agent
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._tail = self._read_tail_hash()

    def _read_tail_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as f:
            last_line = ""
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return GENESIS_HASH
        return AuditEntry.from_json(last_line).entry_hash

    def append(self, action: str, payload: dict[str, Any]) -> AuditEntry:
        ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        entry_hash = _hash_entry(
            timestamp=ts,
            agent=self.agent,
            run_id=self.run_id,
            action=action,
            payload=payload,
            previous_hash=self._tail,
        )
        entry = AuditEntry(
            timestamp=ts,
            agent=self.agent,
            run_id=self.run_id,
            action=action,
            payload=payload,
            previous_hash=self._tail,
            entry_hash=entry_hash,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(entry.to_json() + "\n")
        self._tail = entry_hash
        return entry
