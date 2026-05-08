"""Audit log integrity verification — recompute hashes and check chain links."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from charter.audit import GENESIS_HASH, AuditEntry, _hash_entry


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    entries_checked: int
    broken_at: int | None  # index of first broken entry, or None


def verify_audit_log(path: Path | str) -> VerificationResult:
    p = Path(path)
    if not p.exists():
        return VerificationResult(valid=False, entries_checked=0, broken_at=None)

    expected_prev = GENESIS_HASH
    count = 0
    with p.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line_stripped = line.strip()
            if not line_stripped:
                continue
            entry = AuditEntry.from_json(line_stripped)
            recomputed = _hash_entry(
                timestamp=entry.timestamp,
                agent=entry.agent,
                run_id=entry.run_id,
                action=entry.action,
                payload=entry.payload,
                previous_hash=entry.previous_hash,
            )
            if recomputed != entry.entry_hash or entry.previous_hash != expected_prev:
                return VerificationResult(valid=False, entries_checked=count, broken_at=idx)
            expected_prev = entry.entry_hash
            count += 1
    return VerificationResult(valid=True, entries_checked=count, broken_at=None)
