"""Tests for `audit.schemas` (F.6 Task 4) — OCSF v1.3 API Activity (class_uid 6003).

Production contract:

1. Three pydantic models — `AuditEvent`, `AuditQueryResult`,
   `ChainIntegrityReport`. All `frozen=True`, `extra="forbid"`, JSON
   round-trip clean.
2. Hash columns (`previous_hash`, `entry_hash`) are 64-char hex
   (SHA-256). Validated at construction; non-hex or wrong-length input
   raises ValidationError.
3. `tenant_id` is a 26-char Crockford-base32 ULID; `correlation_id`
   is 32 chars max.
4. OCSF v1.3 constants are exposed and match the spec.
5. `AuditQueryResult` includes both `count_by_action` and
   `count_by_agent` derived views.
6. `ChainIntegrityReport.valid` ↔ `broken_at_correlation_id is None`
   is an enforced invariant.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from audit.schemas import (
    OCSF_ACTIVITY_AUDIT_RECORD,
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    AuditEvent,
    AuditQueryResult,
    ChainIntegrityReport,
)
from pydantic import ValidationError

_HEX64_A = "a" * 64
_HEX64_B = "b" * 64
_HEX64_C = "c" * 64
_TENANT_A = "01HV0T0000000000000000TENA"


def _event(
    *,
    correlation_id: str = "01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    action: str = "episode_appended",
    previous_hash: str = _HEX64_A,
    entry_hash: str = _HEX64_B,
) -> AuditEvent:
    return AuditEvent(
        tenant_id=_TENANT_A,
        correlation_id=correlation_id,
        agent_id="cloud_posture",
        action=action,
        payload={"episode_id": 1},
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        emitted_at=datetime.now(UTC),
        source="jsonl:/var/log/audit.jsonl",
    )


# ---------------------------- OCSF constants ----------------------------


def test_ocsf_constants_match_spec() -> None:
    assert OCSF_VERSION == "1.3.0"
    assert OCSF_CATEGORY_UID == 6  # Application Activity
    assert OCSF_CATEGORY_NAME == "Application Activity"
    assert OCSF_CLASS_UID == 6003  # API Activity — the canonical audit-log class
    assert OCSF_CLASS_NAME == "API Activity"
    # The Nexus-specific activity_id for "audit chain entry" lives at
    # 99 (extension namespace) — keeps the value off the OCSF-reserved range.
    assert OCSF_ACTIVITY_AUDIT_RECORD == 99


# ---------------------------- AuditEvent --------------------------------


def test_audit_event_round_trips_through_json() -> None:
    event = _event()
    payload = event.model_dump_json()
    restored = AuditEvent.model_validate_json(payload)
    assert restored == event


def test_audit_event_is_frozen() -> None:
    event = _event()
    with pytest.raises(ValidationError):
        event.tenant_id = "different"  # type: ignore[misc]


def test_audit_event_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(
            {
                **_event().model_dump(mode="json"),
                "this_field_does_not_exist": 42,
            }
        )


@pytest.mark.parametrize(
    "bad_hash",
    [
        "",
        "a" * 63,  # too short
        "a" * 65,  # too long
        "g" * 64,  # non-hex
        "A" * 64,  # uppercase (canonical hex is lowercase)
    ],
)
def test_audit_event_rejects_malformed_hashes(bad_hash: str) -> None:
    with pytest.raises(ValidationError):
        _event(previous_hash=bad_hash)


def test_audit_event_genesis_previous_hash_is_allowed() -> None:
    """Chain start always carries `previous_hash = "0" * 64` per
    `charter.audit.GENESIS_HASH`.
    """
    event = _event(previous_hash="0" * 64)
    assert event.previous_hash == "0" * 64


def test_audit_event_rejects_oversized_tenant_id() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            tenant_id="x" * 27,
            correlation_id="c",
            agent_id="a",
            action="x",
            payload={},
            previous_hash=_HEX64_A,
            entry_hash=_HEX64_B,
            emitted_at=datetime.now(UTC),
            source="jsonl",
        )


def test_audit_event_rejects_oversized_correlation_id() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            tenant_id=_TENANT_A,
            correlation_id="x" * 33,
            agent_id="a",
            action="x",
            payload={},
            previous_hash=_HEX64_A,
            entry_hash=_HEX64_B,
            emitted_at=datetime.now(UTC),
            source="jsonl",
        )


def test_audit_event_ocsf_envelope_carries_class_uid() -> None:
    """`AuditEvent.to_ocsf()` returns a dict suitable for emission to
    downstream consumers (fabric layer, Meta-Harness).
    """
    event = _event()
    ocsf = event.to_ocsf()
    assert ocsf["class_uid"] == OCSF_CLASS_UID
    assert ocsf["class_name"] == OCSF_CLASS_NAME
    assert ocsf["category_uid"] == OCSF_CATEGORY_UID
    assert ocsf["activity_id"] == OCSF_ACTIVITY_AUDIT_RECORD
    assert ocsf["metadata"]["version"] == OCSF_VERSION
    # The chain hashes survive into the OCSF envelope unmodified — the
    # downstream verifier reaches for them.
    assert ocsf["unmapped"]["previous_hash"] == event.previous_hash
    assert ocsf["unmapped"]["entry_hash"] == event.entry_hash


# ---------------------------- AuditQueryResult --------------------------


def test_audit_query_result_count_by_action_derives_from_events() -> None:
    events = (
        _event(action="episode_appended", entry_hash=_HEX64_B),
        _event(action="episode_appended", entry_hash=_HEX64_C),
        _event(action="entity_upserted", entry_hash="d" * 64),
    )
    result = AuditQueryResult(total=3, events=events)
    assert result.count_by_action == {
        "episode_appended": 2,
        "entity_upserted": 1,
    }


def test_audit_query_result_count_by_agent_derives_from_events() -> None:
    e1 = _event(entry_hash=_HEX64_B).model_copy(update={"agent_id": "cloud_posture"})
    e2 = _event(entry_hash=_HEX64_C).model_copy(update={"agent_id": "runtime_threat"})
    e3 = _event(entry_hash="d" * 64).model_copy(update={"agent_id": "cloud_posture"})
    result = AuditQueryResult(total=3, events=(e1, e2, e3))
    assert result.count_by_agent == {
        "cloud_posture": 2,
        "runtime_threat": 1,
    }


def test_audit_query_result_empty_is_valid() -> None:
    result = AuditQueryResult(total=0, events=())
    assert result.count_by_action == {}
    assert result.count_by_agent == {}


def test_audit_query_result_json_round_trip() -> None:
    events = (_event(),)
    result = AuditQueryResult(total=1, events=events)
    restored = AuditQueryResult.model_validate_json(result.model_dump_json())
    assert restored == result


# ---------------------------- ChainIntegrityReport ----------------------


def test_chain_integrity_report_valid_when_no_break() -> None:
    report = ChainIntegrityReport(
        valid=True,
        entries_checked=10,
        broken_at_correlation_id=None,
        broken_at_action=None,
    )
    assert report.valid


def test_chain_integrity_report_invariant_valid_implies_no_break() -> None:
    """`valid=True` with a broken_at_* set is contradictory and must raise."""
    with pytest.raises(ValidationError):
        ChainIntegrityReport(
            valid=True,
            entries_checked=10,
            broken_at_correlation_id="corr-1",
            broken_at_action="episode_appended",
        )


def test_chain_integrity_report_invariant_invalid_requires_break_location() -> None:
    """`valid=False` without a broken_at_correlation_id is also
    contradictory — the reader can't act on the break without the
    context of which entry broke.
    """
    with pytest.raises(ValidationError):
        ChainIntegrityReport(
            valid=False,
            entries_checked=10,
            broken_at_correlation_id=None,
            broken_at_action=None,
        )


def test_chain_integrity_report_json_round_trip() -> None:
    report = ChainIntegrityReport(
        valid=False,
        entries_checked=3,
        broken_at_correlation_id="corr-bad",
        broken_at_action="episode_appended",
    )
    restored = ChainIntegrityReport.model_validate_json(report.model_dump_json())
    assert restored == report


# ---------------------------- export check ------------------------------


def test_module_all_exports_three_models_plus_constants() -> None:
    import audit.schemas as schemas

    assert {"AuditEvent", "AuditQueryResult", "ChainIntegrityReport"} <= set(schemas.__all__)
    assert "OCSF_CLASS_UID" in schemas.__all__
