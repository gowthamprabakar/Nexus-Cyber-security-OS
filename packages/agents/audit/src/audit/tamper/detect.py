"""Tamper detection + categorization over audit chains (audit v0.2 Task 7, Q5).

Walks a chain and reports **every** integrity break it finds, categorized by tamper type —
where the existing ``verify_audit_chain`` returns only the first break as a boolean. Per
**WI-F2 / WI-F9** this module **only detects + categorizes**; it never repairs and never
mutates the chain (the architectural invariant — v0.3 doesn't get repair either). Read-only.

Tamper categories (the conditions detectable from the v0.2 hash chain):
- ``GENESIS_VIOLATION`` — the first entry's ``previous_hash`` is not the genesis hash.
- ``MISSING_ENTRY`` — an entry's ``previous_hash`` != the prior entry's ``entry_hash``
  (an entry was inserted, deleted, or reordered).
- ``HASH_MISMATCH`` — an entry's ``entry_hash`` != the recomputed hash (a single row edited).
- ``TIMESTAMP_SKEW`` — ``emitted_at`` runs backwards vs the prior entry.

(``SIGNATURE_BREAK`` is reserved for the v0.3 Sigstore epoch signing — not emitted at v0.2.)
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from charter.audit import GENESIS_HASH, _hash_entry

from audit.schemas import AuditEvent


class TamperCategory(StrEnum):
    GENESIS_VIOLATION = "genesis_violation"
    MISSING_ENTRY = "missing_entry"
    HASH_MISMATCH = "hash_mismatch"
    TIMESTAMP_SKEW = "timestamp_skew"


@dataclass(frozen=True, slots=True)
class TamperFinding:
    category: TamperCategory
    correlation_id: str
    action: str
    detail: str


def _recompute(event: AuditEvent) -> str:
    return _hash_entry(
        timestamp=event.emitted_at.isoformat().replace("+00:00", "Z"),
        agent=event.agent_id,
        run_id=event.correlation_id,
        action=event.action,
        payload=event.payload,
        previous_hash=event.previous_hash,
    )


def detect_tampering(events: Sequence[AuditEvent]) -> tuple[TamperFinding, ...]:
    """Return every tamper finding in ``events`` (empty tuple == intact chain). Detect-only."""
    findings: list[TamperFinding] = []
    expected_previous = GENESIS_HASH
    prev_time = None
    for i, event in enumerate(events):
        if i == 0 and event.previous_hash != GENESIS_HASH:
            findings.append(
                TamperFinding(
                    TamperCategory.GENESIS_VIOLATION,
                    event.correlation_id,
                    event.action,
                    "first entry not rooted at genesis hash",
                )
            )
        elif event.previous_hash != expected_previous:
            findings.append(
                TamperFinding(
                    TamperCategory.MISSING_ENTRY,
                    event.correlation_id,
                    event.action,
                    "previous_hash does not match the prior entry_hash (insert/delete/reorder)",
                )
            )
        if _recompute(event) != event.entry_hash:
            findings.append(
                TamperFinding(
                    TamperCategory.HASH_MISMATCH,
                    event.correlation_id,
                    event.action,
                    "entry_hash does not match the recomputed hash (row edited)",
                )
            )
        if prev_time is not None and event.emitted_at < prev_time:
            findings.append(
                TamperFinding(
                    TamperCategory.TIMESTAMP_SKEW,
                    event.correlation_id,
                    event.action,
                    "emitted_at runs backwards vs the prior entry",
                )
            )
        prev_time = event.emitted_at
        expected_previous = event.entry_hash
    return tuple(findings)


def is_intact(events: Sequence[AuditEvent]) -> bool:
    """True iff no tamper finding is detected."""
    return not detect_tampering(events)
