"""audit v0.2 Task 10 — typed-filter execution engine + projection tests (Q3/Q6)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from audit.query.engine import apply_filter, project
from audit.query.typed_filter import TypedAuditFilter
from audit.schemas import AuditEvent

_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"
_BASE = datetime(2026, 5, 1, tzinfo=UTC)


def _event(
    *, agent="cloud_posture", action="scan", tenant=_TENANT_A, offset=0, status=None
) -> AuditEvent:
    payload = {"status": status} if status is not None else {}
    return AuditEvent(
        tenant_id=tenant,
        correlation_id=f"corr-{offset:03d}",
        agent_id=agent,
        action=action,
        payload=payload,
        previous_hash="0" * 64,
        entry_hash="1" * 64,
        emitted_at=_BASE + timedelta(seconds=offset),
        source="jsonl:/tmp/a.jsonl",
    )


def test_tenant_isolation() -> None:
    events = [_event(tenant=_TENANT_A), _event(tenant=_TENANT_B, offset=1)]
    out = apply_filter(events, TypedAuditFilter(tenant_id=_TENANT_A))
    assert len(out) == 1 and out[0].tenant_id == _TENANT_A


def test_filter_by_action() -> None:
    events = [_event(action="scan"), _event(action="emit", offset=1)]
    out = apply_filter(events, TypedAuditFilter(tenant_id=_TENANT_A, action="emit"))
    assert [e.action for e in out] == ["emit"]


def test_filter_by_agent() -> None:
    events = [_event(agent="cloud_posture"), _event(agent="compliance", offset=1)]
    out = apply_filter(events, TypedAuditFilter(tenant_id=_TENANT_A, agent_id="compliance"))
    assert [e.agent_id for e in out] == ["compliance"]


def test_filter_by_time_range() -> None:
    events = [_event(offset=i) for i in range(5)]
    flt = TypedAuditFilter(
        tenant_id=_TENANT_A, since=_BASE + timedelta(seconds=1), until=_BASE + timedelta(seconds=3)
    )
    out = apply_filter(events, flt)
    assert [e.correlation_id for e in out] == ["corr-001", "corr-002", "corr-003"]


def test_filter_by_status_payload() -> None:
    events = [_event(status="success"), _event(status="failure", offset=1)]
    out = apply_filter(events, TypedAuditFilter(tenant_id=_TENANT_A, status="failure"))
    assert [e.payload["status"] for e in out] == ["failure"]


def test_combined_filter() -> None:
    events = [
        _event(agent="compliance", action="emit", offset=0),
        _event(agent="compliance", action="scan", offset=1),
        _event(agent="cloud_posture", action="emit", offset=2),
    ]
    flt = TypedAuditFilter(tenant_id=_TENANT_A, agent_id="compliance", action="emit")
    assert len(apply_filter(events, flt)) == 1


def test_projection_selects_fields() -> None:
    out = project([_event()], ["agent_id", "action"])
    assert out == ({"agent_id": "cloud_posture", "action": "scan"},)


def test_projection_unknown_field_raises() -> None:
    with pytest.raises(ValueError, match="unknown projection field"):
        project([_event()], ["agent_id", "secret"])


def test_empty_events() -> None:
    assert apply_filter([], TypedAuditFilter(tenant_id=_TENANT_A)) == ()
    assert project([], ["action"]) == ()
