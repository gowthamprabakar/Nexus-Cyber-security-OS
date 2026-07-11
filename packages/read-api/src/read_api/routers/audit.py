"""Audit router — tenant-scoped audit log (F.6 OCSF 6003 API-Activity events).

Audit events live in the ``audit_events`` table (a tamper-evident hash chain),
separate from the entity graph, and are read through ``AuditStore.query`` — which
scopes every query by ``tenant_id`` at the SQL layer.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from audit.chain import verify_audit_chain
from audit.schemas import AuditEvent
from audit.store import AuditStore
from fastapi import APIRouter, Depends, Query

from read_api.deps import (
    Envelope,
    get_audit_store,
    make_envelope,
    require_entitlement,
    require_tenant,
)

router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    dependencies=[Depends(require_entitlement("audit", "read"))],
)

# Verification loads events into memory to walk the hash chain; cap the scan and
# report `complete` so a truncated verdict never masquerades as a whole-chain one.
_VERIFY_SCAN_LIMIT = 10000


@router.get("", response_model=Envelope)
async def list_audit_events(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    action: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    tenant: str = Depends(require_tenant),
    store: AuditStore = Depends(get_audit_store),  # noqa: B008
) -> Envelope:
    """Audit chain entries for the tenant, chronological, paginated.

    ``AuditStore.query`` returns the full ``total`` plus up to ``limit`` events;
    fetch ``offset + limit`` and slice for offset pagination. Chain-internal
    fields (hashes, payload) are omitted from the list view.
    """
    # ponytail: AuditStore.query orders oldest-first; newest-first would need an
    # `order` arg on the store — add it when the log view calls for reverse order.
    result = await store.query(
        tenant_id=tenant, action=action, agent_id=agent_id, limit=offset + limit
    )
    window = result.events[offset : offset + limit]
    items: list[dict[str, Any]] = [
        {
            "emitted_at": e.emitted_at.isoformat(),
            "agent_id": e.agent_id,
            "action": e.action,
            "correlation_id": e.correlation_id,
            "source": e.source,
        }
        for e in window
    ]
    next_offset: int | None = offset + limit if offset + limit < result.total else None
    return make_envelope(data=items, offset=next_offset, total=result.total, tenant=tenant)


def _verify_chains(events: Sequence[AuditEvent]) -> dict[str, Any]:
    """Verify each source's chain with the correct mode and aggregate.

    Each distinct ``source`` is its own chain: a ``jsonl:*`` source roots at
    GENESIS and is chain-linked (sequential), a ``memory:*`` source is per-entry
    only. Verifying a tenant's mixed events under one mode would give a false
    verdict, so group by source first and pick the mode per group.
    """
    by_source: dict[str, list[AuditEvent]] = {}
    for event in events:
        by_source.setdefault(event.source, []).append(event)

    valid = True
    entries_checked = 0
    broken_cid: str | None = None
    broken_action: str | None = None
    for source, group in by_source.items():
        report = verify_audit_chain(group, sequential=source.startswith("jsonl:"))
        entries_checked += report.entries_checked
        if not report.valid and valid:  # keep the first break encountered
            valid = False
            broken_cid = report.broken_at_correlation_id
            broken_action = report.broken_at_action
    return {
        "valid": valid,
        "entries_checked": entries_checked,
        "chains_checked": len(by_source),
        "broken_at_correlation_id": broken_cid,
        "broken_at_action": broken_action,
    }


@router.get("/verify", response_model=Envelope)
async def verify_audit_events(
    tenant: str = Depends(require_tenant),
    store: AuditStore = Depends(get_audit_store),  # noqa: B008
) -> Envelope:
    """Tamper-evidence verdict for the tenant's audit chain(s).

    ``complete`` is false when the tenant has more events than the scan cap, so a
    partial verification never reads as a whole-chain guarantee.
    """
    result = await store.query(tenant_id=tenant, limit=_VERIFY_SCAN_LIMIT)
    data = _verify_chains(result.events)
    data["total_events"] = result.total
    data["complete"] = len(result.events) >= result.total
    return make_envelope(data=data, offset=None, total=None, tenant=tenant)
