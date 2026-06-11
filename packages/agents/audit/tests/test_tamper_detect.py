"""audit v0.2 Task 7 — tamper detection + categorization tests (Q5/WI-F2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import audit.tamper.detect as mod
from audit.schemas import AuditEvent
from audit.tamper.detect import TamperCategory, detect_tampering, is_intact
from charter.audit import GENESIS_HASH, _hash_entry

_TENANT = "01HV0T0000000000000000TENA"


def _chain(actions: list[str]) -> list[AuditEvent]:
    events: list[AuditEvent] = []
    previous_hash = GENESIS_HASH
    base = datetime(2026, 5, 1, tzinfo=UTC)
    for i, action in enumerate(actions):
        emitted_at = base + timedelta(seconds=i)
        ts = emitted_at.isoformat().replace("+00:00", "Z")
        payload = {"i": i}
        entry_hash = _hash_entry(
            timestamp=ts,
            agent="cloud_posture",
            run_id=f"corr-{i:03d}",
            action=action,
            payload=payload,
            previous_hash=previous_hash,
        )
        events.append(
            AuditEvent(
                tenant_id=_TENANT,
                correlation_id=f"corr-{i:03d}",
                agent_id="cloud_posture",
                action=action,
                payload=payload,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                emitted_at=emitted_at,
                source="jsonl:/tmp/a.jsonl",
            )
        )
        previous_hash = entry_hash
    return events


def test_intact_chain_no_findings() -> None:
    events = _chain(["a", "b", "c"])
    assert detect_tampering(events) == () and is_intact(events) is True


def test_empty_chain_intact() -> None:
    assert detect_tampering([]) == () and is_intact([]) is True


def test_hash_mismatch_detected() -> None:
    events = _chain(["a", "b"])
    events[1] = events[1].model_copy(update={"action": "TAMPERED"})  # entry_hash now stale
    cats = {f.category for f in detect_tampering(events)}
    assert TamperCategory.HASH_MISMATCH in cats


def test_genesis_violation_detected() -> None:
    events = _chain(["a"])
    events[0] = events[0].model_copy(update={"previous_hash": "f" * 64})
    cats = {f.category for f in detect_tampering(events)}
    assert TamperCategory.GENESIS_VIOLATION in cats


def test_missing_entry_detected() -> None:
    events = _chain(["a", "b", "c"])
    # Delete the middle entry -> entry c's previous_hash no longer matches a's entry_hash.
    tampered = [events[0], events[2]]
    cats = {f.category for f in detect_tampering(tampered)}
    assert TamperCategory.MISSING_ENTRY in cats


def test_timestamp_skew_detected() -> None:
    events = _chain(["a", "b"])
    past = events[0].emitted_at - timedelta(days=1)
    events[1] = events[1].model_copy(update={"emitted_at": past})
    cats = {f.category for f in detect_tampering(events)}
    assert TamperCategory.TIMESTAMP_SKEW in cats


def test_finding_carries_provenance() -> None:
    events = _chain(["a"])
    events[0] = events[0].model_copy(update={"previous_hash": "f" * 64})
    [finding] = [
        f for f in detect_tampering(events) if f.category == TamperCategory.GENESIS_VIOLATION
    ]
    assert finding.correlation_id == "corr-000" and finding.action == "a"


def test_no_repair_surface() -> None:
    # WI-F2: detect-only — no repair / mutate / fix function exists.
    for name in ("repair", "fix", "mutate", "rebuild_chain"):
        assert not hasattr(mod, name)
