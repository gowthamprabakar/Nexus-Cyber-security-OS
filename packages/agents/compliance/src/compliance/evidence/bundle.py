"""Audit-ready evidence bundle schema (compliance v0.2 Task 15).

Per **Q6** an evidence bundle is the auditor-facing artifact: one entry per control carrying
framework + control id + PASS/FAIL status + the source finding ids + a timestamp + a content
**hash**. This task defines the schema + the deterministic per-entry hash; the hash **chain**
+ signed manifest are Task 16, and the per-framework PDF/JSON exports are Task 17.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any


def _hash_content(content: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceEntry:
    framework_id: str
    control_id: str
    status: str  # "pass" | "fail" | "not_evaluated"
    source_finding_ids: tuple[str, ...]
    timestamp: str
    entry_hash: str

    def content(self) -> dict[str, Any]:
        """The hashed content (everything except the hash itself)."""
        return {
            "framework_id": self.framework_id,
            "control_id": self.control_id,
            "status": self.status,
            "source_finding_ids": list(self.source_finding_ids),
            "timestamp": self.timestamp,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.content(), "entry_hash": self.entry_hash}


def build_evidence_entry(
    *,
    framework_id: str,
    control_id: str,
    status: str,
    source_finding_ids: Iterable[str],
    timestamp: str,
) -> EvidenceEntry:
    """Build an evidence entry with its deterministic content hash."""
    finding_ids = tuple(source_finding_ids)
    content = {
        "framework_id": framework_id,
        "control_id": control_id,
        "status": status,
        "source_finding_ids": list(finding_ids),
        "timestamp": timestamp,
    }
    return EvidenceEntry(
        framework_id=framework_id,
        control_id=control_id,
        status=status,
        source_finding_ids=finding_ids,
        timestamp=timestamp,
        entry_hash=_hash_content(content),
    )


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    framework_id: str
    generated_at: str
    entries: tuple[EvidenceEntry, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "generated_at": self.generated_at,
            "entry_count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
        }


def build_evidence_bundle(
    *, framework_id: str, generated_at: str, entries: Sequence[EvidenceEntry]
) -> EvidenceBundle:
    return EvidenceBundle(
        framework_id=framework_id, generated_at=generated_at, entries=tuple(entries)
    )
