"""audit v0.2 Task 8 — tamper-alert OCSF 6003 emission tests (Q5/WI-F9)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from audit.schemas import AuditEvent
from audit.tamper.alert import (
    OCSF_SEVERITY_CRITICAL,
    build_tamper_alert,
    emit_tamper_alerts,
)
from audit.tamper.detect import detect_tampering
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


def test_intact_chain_no_alerts() -> None:
    assert emit_tamper_alerts("chain-1", _chain(["a", "b"])) == ()


def test_broken_chain_always_alerts() -> None:
    # WI-F9: a break always surfaces an alert.
    events = _chain(["a", "b"])
    events[1] = events[1].model_copy(update={"action": "TAMPERED"})
    alerts = emit_tamper_alerts("chain-1", events)
    assert len(alerts) >= 1


def test_alert_is_ocsf_6003() -> None:
    events = _chain(["a", "b"])
    events[1] = events[1].model_copy(update={"action": "X"})
    alert = emit_tamper_alerts("chain-1", events)[0]
    assert alert["class_uid"] == 6003 and alert["severity_id"] == OCSF_SEVERITY_CRITICAL


def test_alert_carries_required_fields() -> None:
    events = _chain(["a", "b"])
    events[1] = events[1].model_copy(update={"action": "X"})
    unmapped = emit_tamper_alerts("chain-7", events)[0]["unmapped"]
    assert unmapped["broken_chain_id"] == "chain-7"
    assert unmapped["suspected_tamper_point"] == "corr-001"
    assert unmapped["last_valid_entry"] == "corr-000"
    assert "tamper_category" in unmapped


def test_last_valid_entry_genesis_for_first_break() -> None:
    from audit.tamper.detect import TamperCategory

    events = _chain(["a"])
    events[0] = events[0].model_copy(update={"previous_hash": "f" * 64})
    # Editing previous_hash trips both GENESIS_VIOLATION and HASH_MISMATCH — pick the former.
    finding = next(
        f for f in detect_tampering(events) if f.category == TamperCategory.GENESIS_VIOLATION
    )
    alert = build_tamper_alert("chain-1", events, finding)
    assert alert["unmapped"]["last_valid_entry"] == "genesis"


def test_one_alert_per_finding() -> None:
    events = _chain(["a", "b"])
    # Edit entry 1: both a hash-mismatch and a (possible) link consequence -> >=1 finding.
    events[1] = events[1].model_copy(update={"action": "X"})
    assert len(emit_tamper_alerts("c", events)) == len(detect_tampering(events))


def test_operation_is_tamper_alert() -> None:
    events = _chain(["a", "b"])
    events[1] = events[1].model_copy(update={"action": "X"})
    assert emit_tamper_alerts("c", events)[0]["api"]["operation"] == "tamper_alert"
