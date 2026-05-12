"""`episode_audit_read` — F.5 `episodes`-table ingest as audit events.

Surfaces agent-run events stored in F.5's `episodes` table as F.6 audit
events. The episodes table is **not** chain-structured in F.5 (the hash
chain lives in `charter.audit.AuditLog`'s jsonl files); F.6 roots each
event at `GENESIS_HASH` and computes a per-event `entry_hash` over the
same canonical fields `charter.audit._hash_entry` uses.

The Task-8 verifier handles `source = "memory:*"` events in non-sequential
mode — per-entry hash recompute only, no `previous_hash` chain-link
check. That matches the source's nature: the episodes table is a flat
record of agent activity, not a tamper-evident chain.

Per ADR-005 this is an async wrapper — but unlike the filesystem JSONL
reader, the SQLAlchemy session execute is already async, so no
`asyncio.to_thread` indirection is needed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from charter.audit import GENESIS_HASH, _hash_entry
from charter.memory.models import EpisodeModel
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from audit.schemas import AuditEvent


async def episode_audit_read(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    tenant_id: str,
    since: datetime | None = None,
    until: datetime | None = None,
) -> tuple[AuditEvent, ...]:
    """Read episodes for a tenant and convert to `AuditEvent` shape.

    Results are ordered by `(emitted_at, episode_id)` ascending so the
    deterministic-hash property holds across reads.
    """
    clauses: list[Any] = [EpisodeModel.tenant_id == tenant_id]
    if since is not None:
        clauses.append(EpisodeModel.emitted_at >= since)
    if until is not None:
        clauses.append(EpisodeModel.emitted_at <= until)

    stmt = (
        select(EpisodeModel)
        .where(*clauses)
        .order_by(EpisodeModel.emitted_at, EpisodeModel.episode_id)
    )
    async with session_factory() as session:
        models = (await session.execute(stmt)).scalars().all()

    source = f"memory:{tenant_id}"
    events = [_to_audit_event(m, source=source) for m in models]
    return tuple(e for e in events if e is not None)


def _to_audit_event(model: EpisodeModel, *, source: str) -> AuditEvent | None:
    payload = dict(model.payload)
    timestamp = _normalize_timestamp(model.emitted_at)
    entry_hash = _hash_entry(
        timestamp=timestamp.isoformat().replace("+00:00", "Z"),
        agent=model.agent_id,
        run_id=model.correlation_id,
        action=model.action,
        payload=payload,
        previous_hash=GENESIS_HASH,
    )
    try:
        return AuditEvent(
            tenant_id=model.tenant_id,
            correlation_id=model.correlation_id,
            agent_id=model.agent_id,
            action=model.action,
            payload=payload,
            previous_hash=GENESIS_HASH,
            entry_hash=entry_hash,
            emitted_at=timestamp,
            source=source,
        )
    except ValidationError:
        return None


def _normalize_timestamp(value: datetime) -> datetime:
    """SQLite drops timezone info on TIMESTAMPTZ round-trip; pin to UTC
    so downstream consumers always see a timezone-aware datetime.
    """
    from datetime import UTC

    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


__all__ = ["episode_audit_read"]
