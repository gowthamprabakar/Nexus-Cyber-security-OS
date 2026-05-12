"""Tests for `audit.chain.verify_audit_chain` (F.6 Task 8).

Production contract:

- Takes a `Sequence[AuditEvent]` and a `sequential: bool` flag.
- Returns `ChainIntegrityReport` (the Task-4 pydantic model).
- `sequential=True`: enforces chain linkage — each event's
  `previous_hash` must equal the prior event's `entry_hash`, with the
  first event rooted at `charter.audit.GENESIS_HASH`. Also recomputes
  each entry's own `entry_hash` to detect tampering.
- `sequential=False`: per-entry recompute only — useful for sources
  like `memory:*` (the F.5 episode reader) where events are not
  chain-linked.
- Empty input → `valid=True, entries_checked=0`.
- Tamper detection reports the breaking event's `correlation_id` +
  `action` so the operator console can pin them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from audit.chain import verify_audit_chain
from audit.schemas import AuditEvent
from charter.audit import GENESIS_HASH, _hash_entry

_TENANT_A = "01HV0T0000000000000000TENA"


def _build_chain(actions: list[str]) -> list[AuditEvent]:
    """Build a hash-chained list of `len(actions)` events.

    Each event's `entry_hash` is computed off the previous entry's
    `entry_hash` so the chain is real (matches what `AuditLog.append`
    would have produced).
    """
    events: list[AuditEvent] = []
    previous_hash = GENESIS_HASH
    base = datetime(2026, 5, 1, tzinfo=UTC)
    for i, action in enumerate(actions):
        emitted_at = base + timedelta(seconds=i)
        timestamp_str = emitted_at.isoformat().replace("+00:00", "Z")
        payload = {"i": i}
        entry_hash = _hash_entry(
            timestamp=timestamp_str,
            agent="cloud_posture",
            run_id=f"corr-{i:03d}",
            action=action,
            payload=payload,
            previous_hash=previous_hash,
        )
        events.append(
            AuditEvent(
                tenant_id=_TENANT_A,
                correlation_id=f"corr-{i:03d}",
                agent_id="cloud_posture",
                action=action,
                payload=payload,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                emitted_at=emitted_at,
                source="jsonl:/tmp/audit.jsonl",
            )
        )
        previous_hash = entry_hash
    return events


# ---------------------------- happy path -------------------------------


def test_verify_audit_chain_empty_input_is_valid() -> None:
    report = verify_audit_chain([], sequential=True)
    assert report.valid
    assert report.entries_checked == 0
    assert report.broken_at_correlation_id is None


def test_verify_audit_chain_sequential_clean_chain_is_valid() -> None:
    chain = _build_chain(["a", "b", "c"])
    report = verify_audit_chain(chain, sequential=True)
    assert report.valid
    assert report.entries_checked == 3


def test_verify_audit_chain_per_entry_clean_set_is_valid() -> None:
    """`sequential=False` recomputes each entry's own hash; a clean
    chain trivially passes that check too.
    """
    chain = _build_chain(["a", "b", "c"])
    report = verify_audit_chain(chain, sequential=False)
    assert report.valid
    assert report.entries_checked == 3


# ---------------------------- single-tamper detection ------------------


def test_verify_audit_chain_detects_tampered_entry_hash() -> None:
    """Mutate the middle entry's payload — its recomputed hash no longer
    matches the stored one. Sequential mode catches it; non-sequential
    catches it too.
    """
    chain = _build_chain(["a", "b", "c"])
    tampered = chain.copy()
    tampered[1] = chain[1].model_copy(update={"payload": {"i": 999}})

    for sequential in (True, False):
        report = verify_audit_chain(tampered, sequential=sequential)
        assert not report.valid
        assert report.broken_at_correlation_id == "corr-001"
        assert report.broken_at_action == "b"


def test_verify_audit_chain_sequential_detects_broken_link() -> None:
    """Mutate the middle entry's `previous_hash` — leaves its own
    `entry_hash` matching the (new, wrong) `previous_hash`, so the
    per-entry check would have passed. Only sequential mode catches it.
    """
    chain = _build_chain(["a", "b", "c"])
    bogus_previous = "f" * 64
    new_entry_hash = _hash_entry(
        timestamp=chain[1].emitted_at.isoformat().replace("+00:00", "Z"),
        agent=chain[1].agent_id,
        run_id=chain[1].correlation_id,
        action=chain[1].action,
        payload=chain[1].payload,
        previous_hash=bogus_previous,
    )
    forged = chain[1].model_copy(
        update={"previous_hash": bogus_previous, "entry_hash": new_entry_hash}
    )
    chain[1] = forged

    seq_report = verify_audit_chain(chain, sequential=True)
    assert not seq_report.valid
    assert seq_report.broken_at_correlation_id == "corr-001"

    # Non-sequential mode misses chain-link tampering — only per-entry
    # hashes are checked, and the forged entry's own hash is internally
    # consistent with its (false) previous_hash.
    non_seq_report = verify_audit_chain(chain, sequential=False)
    assert non_seq_report.valid


# ---------------------------- chain root + ordering --------------------


def test_verify_audit_chain_first_event_must_root_at_genesis() -> None:
    """A clean chain's first event has `previous_hash == GENESIS_HASH`.
    A chain whose first event roots elsewhere is rejected in
    sequential mode.
    """
    chain = _build_chain(["a", "b"])
    # Recompute first event with a bogus previous_hash but consistent entry_hash.
    bogus = "1" * 64
    e0 = chain[0]
    timestamp_str = e0.emitted_at.isoformat().replace("+00:00", "Z")
    forged_first = e0.model_copy(
        update={
            "previous_hash": bogus,
            "entry_hash": _hash_entry(
                timestamp=timestamp_str,
                agent=e0.agent_id,
                run_id=e0.correlation_id,
                action=e0.action,
                payload=e0.payload,
                previous_hash=bogus,
            ),
        }
    )
    chain[0] = forged_first

    report = verify_audit_chain(chain, sequential=True)
    assert not report.valid
    assert report.broken_at_correlation_id == "corr-000"


def test_verify_audit_chain_single_event_clean_genesis_root_is_valid() -> None:
    """One-event chain rooted at GENESIS_HASH is the minimal valid chain."""
    chain = _build_chain(["a"])
    report = verify_audit_chain(chain, sequential=True)
    assert report.valid
    assert report.entries_checked == 1


# ---------------------------- helper output shape ----------------------


def test_verify_audit_chain_returns_chain_integrity_report() -> None:
    from audit.schemas import ChainIntegrityReport

    report = verify_audit_chain([], sequential=True)
    assert isinstance(report, ChainIntegrityReport)
