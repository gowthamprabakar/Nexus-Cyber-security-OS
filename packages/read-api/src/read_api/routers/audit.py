"""Audit router — tenant-scoped audit log (F.6 OCSF 6003 API-Activity events).

Audit events live in the ``audit_events`` table (a tamper-evident hash chain),
separate from the entity graph, and are read through ``AuditStore.query`` — which
scopes every query by ``tenant_id`` at the SQL layer.
"""

from __future__ import annotations

from typing import Any

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
