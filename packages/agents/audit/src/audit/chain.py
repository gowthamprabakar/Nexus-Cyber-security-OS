"""Chain-integrity verifier for in-memory `AuditEvent` sequences (F.6 Task 8).

Wraps `charter.audit._hash_entry` to validate a `Sequence[AuditEvent]`
in two modes:

- **`sequential=True`** — full chain validation. Each event's
  `previous_hash` must equal the prior event's `entry_hash`, and the
  first event must root at `charter.audit.GENESIS_HASH`. Each entry's
  own `entry_hash` is also recomputed to detect single-row tampering.
  Use this for `source = "jsonl:*"` events that came out of a real
  `AuditLog`-emitted chain.
- **`sequential=False`** — per-entry hash recompute only. No
  chain-link enforcement. Use this for `source = "memory:*"` events
  where the underlying table isn't chain-structured and F.6's reader
  roots every event at GENESIS_HASH independently.

Returns a `ChainIntegrityReport` (Task-4 pydantic model). The report's
invariant (valid ↔ broken_at_correlation_id is None) is enforced by
the model itself.

The verifier deliberately stops at the **first** break — operators
fix one break at a time, and reporting downstream errors that may
cascade from the first break is noise.
"""

from __future__ import annotations

from collections.abc import Sequence

from charter.audit import GENESIS_HASH, _hash_entry

from audit.schemas import AuditEvent, ChainIntegrityReport


def verify_audit_chain(
    events: Sequence[AuditEvent],
    *,
    sequential: bool,
) -> ChainIntegrityReport:
    """Validate the chain integrity of `events`.

    `sequential=True` enforces both per-entry hash + chain-link;
    `sequential=False` skips the chain-link check (suitable for
    sources where events are not chain-structured).
    """
    if not events:
        return ChainIntegrityReport(
            valid=True,
            entries_checked=0,
            broken_at_correlation_id=None,
            broken_at_action=None,
        )

    expected_previous = GENESIS_HASH
    checked = 0
    for event in events:
        if sequential and event.previous_hash != expected_previous:
            return ChainIntegrityReport(
                valid=False,
                entries_checked=checked,
                broken_at_correlation_id=event.correlation_id,
                broken_at_action=event.action,
            )

        recomputed = _hash_entry(
            timestamp=event.emitted_at.isoformat().replace("+00:00", "Z"),
            agent=event.agent_id,
            run_id=event.correlation_id,
            action=event.action,
            payload=event.payload,
            previous_hash=event.previous_hash,
        )
        if recomputed != event.entry_hash:
            return ChainIntegrityReport(
                valid=False,
                entries_checked=checked,
                broken_at_correlation_id=event.correlation_id,
                broken_at_action=event.action,
            )

        expected_previous = event.entry_hash
        checked += 1

    return ChainIntegrityReport(
        valid=True,
        entries_checked=checked,
        broken_at_correlation_id=None,
        broken_at_action=None,
    )


__all__ = ["verify_audit_chain"]
