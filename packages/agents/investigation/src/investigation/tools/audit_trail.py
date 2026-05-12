"""`audit_trail_query` — F.6 AuditStore consumer for D.7 (Task 3).

Thin async wrapper around `audit.store.AuditStore.query` scoped to D.7's
needs. The investigation pipeline calls this to pull the cross-agent
action history for an incident window.

Per ADR-005 the tool is `async` so the agent driver can fan it out via
`asyncio.TaskGroup` alongside other ingest tools (memory walk in Task 4,
sibling-findings reads in Task 5).

D.7 caps results at 500 in v0.1 to keep memory bounded during sub-agent
fan-out — a deep investigation that needs more pages the result via
multiple time-window queries rather than one giant fetch. Configurable
via `limit=` for advanced operators.
"""

from __future__ import annotations

from datetime import datetime

from audit.schemas import AuditEvent
from audit.store import AuditStore


async def audit_trail_query(
    *,
    audit_store: AuditStore,
    tenant_id: str,
    since: datetime | None,
    until: datetime | None,
    action: str | None = None,
    agent_id: str | None = None,
    correlation_id: str | None = None,
    limit: int = 500,
) -> tuple[AuditEvent, ...]:
    """Pull a tuple of `AuditEvent` for the given tenant + window + filters.

    Pre-condition: the underlying `AuditStore` already has the events
    (operator ran `audit-agent run` first, or the eval runner seeded
    them). This tool is a read-only consumer; it does **not** ingest.

    Returns events ordered by `(emitted_at, audit_event_id)` ascending —
    same shape `AuditStore.query` produces. Empty result is a clean ().
    """
    result = await audit_store.query(
        tenant_id=tenant_id,
        since=since,
        until=until,
        action=action,
        agent_id=agent_id,
        correlation_id=correlation_id,
        limit=limit,
    )
    return result.events


__all__ = ["audit_trail_query"]
