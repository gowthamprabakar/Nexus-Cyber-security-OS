"""Typed-filter execution engine + result projection (audit v0.2 Task 10, Q3/Q6).

Applies a ``TypedAuditFilter`` to a sequence of audit events and projects the result down to a
chosen field set. **Tenant isolation is enforced here as defense-in-depth** with F.5 RLS: an
event whose ``tenant_id`` differs from the filter's is dropped even if it reaches the engine
(Q6). ``status`` matches ``payload["status"]``. Pure + deterministic; read-only.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from audit.query.typed_filter import TypedAuditFilter
from audit.schemas import AuditEvent

#: Fields a query result may project (chain hashes + provenance + the typed dimensions).
PROJECTABLE_FIELDS = frozenset(
    {
        "tenant_id",
        "correlation_id",
        "agent_id",
        "action",
        "emitted_at",
        "source",
        "entry_hash",
        "previous_hash",
        "payload",
    }
)


def apply_filter(events: Sequence[AuditEvent], flt: TypedAuditFilter) -> tuple[AuditEvent, ...]:
    """Return the events matching every set dimension of ``flt``. Tenant isolation is always
    enforced (Q6 defense-in-depth)."""
    out: list[AuditEvent] = []
    for event in events:
        if event.tenant_id != flt.tenant_id:
            continue
        if flt.since is not None and event.emitted_at < flt.since:
            continue
        if flt.until is not None and event.emitted_at > flt.until:
            continue
        if flt.action is not None and event.action != flt.action:
            continue
        if flt.agent_id is not None and event.agent_id != flt.agent_id:
            continue
        if flt.status is not None and event.payload.get("status") != flt.status:
            continue
        out.append(event)
    return tuple(out)


def project(events: Sequence[AuditEvent], fields: Sequence[str]) -> tuple[dict[str, Any], ...]:
    """Project each event down to ``fields`` (must be a subset of ``PROJECTABLE_FIELDS``)."""
    unknown = set(fields) - PROJECTABLE_FIELDS
    if unknown:
        raise ValueError(f"unknown projection field(s): {sorted(unknown)}")
    return tuple({f: getattr(event, f) for f in fields} for event in events)
