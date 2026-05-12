"""`AuditStore` — typed async accessor over `audit_events` (F.6 Task 5).

The F.6 read-write seam. Wraps the `audit_events` table behind:

- `ingest(*, tenant_id, events)` — append-only, idempotent on
  `(tenant_id, entry_hash)`. The unique constraint shipped in F.6 Task 2
  drops duplicate inserts at the schema level; the store uses a
  dialect-portable INSERT ... ON CONFLICT DO NOTHING so re-ingesting
  the same `audit.jsonl` file is a clean no-op.
- `query(*, tenant_id, ...)` — five-axis filter (`since`, `until`,
  `action`, `agent_id`, `correlation_id`) plus a default limit. Returns
  the typed `AuditQueryResult` pydantic shape from Task 4 so callers
  stay decoupled from the ORM model.
- `count_by_action(*, tenant_id, since, until)` — fast aggregation
  for the operator console's "what action types fired in this window"
  histogram.

Tenant isolation is enforced by the application-side `WHERE tenant_id`
filter every method applies and by the Postgres RLS policy installed
in `0003_audit_events` (Task 3). On aiosqlite RLS is a no-op; the
application filter alone provides isolation during unit tests.

Construction takes the same `async_sessionmaker[AsyncSession]` seam
the F.5 stores use — no other coupling to the underlying engine.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from charter.memory.models import AuditEventModel
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql.dml import Insert

from audit.schemas import AuditEvent, AuditQueryResult


class AuditStore:
    """Typed async accessor over the `audit_events` table."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def ingest(
        self,
        *,
        tenant_id: str,
        events: Sequence[AuditEvent],
    ) -> int:
        """Append events idempotently. Returns the count of newly inserted rows.

        Idempotency rests on the `(tenant_id, entry_hash)` UNIQUE constraint
        from `0001_memory_baseline` extended by F.6 Task 2: a conflict
        becomes a no-op via INSERT ... ON CONFLICT DO NOTHING. SQLite and
        Postgres both support the construct under SQLAlchemy 2.0's
        dialect-specific `insert()` helpers.
        """
        if not events:
            return 0
        rows = [self._row_dict(tenant_id=tenant_id, event=event) for event in events]
        async with self._session_factory.begin() as session:
            dialect = session.bind.dialect.name if session.bind else ""
            stmt: Insert
            if dialect == "postgresql":
                stmt = (
                    postgres_insert(AuditEventModel)
                    .values(rows)
                    .on_conflict_do_nothing(
                        index_elements=["tenant_id", "entry_hash"],
                    )
                )
            else:
                stmt = (
                    sqlite_insert(AuditEventModel)
                    .values(rows)
                    .on_conflict_do_nothing(
                        index_elements=["tenant_id", "entry_hash"],
                    )
                )
            cursor_result: CursorResult[Any] = await session.execute(stmt)  # type: ignore[assignment]
            return int(cursor_result.rowcount or 0)

    async def query(
        self,
        *,
        tenant_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
        action: str | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
        limit: int = 1000,
    ) -> AuditQueryResult:
        """Return the matching audit events as an `AuditQueryResult`."""
        async with self._session_factory() as session:
            base_filter = self._base_filter(
                tenant_id=tenant_id,
                since=since,
                until=until,
                action=action,
                agent_id=agent_id,
                correlation_id=correlation_id,
            )

            total_stmt = select(func.count()).select_from(AuditEventModel).where(*base_filter)
            total = int((await session.execute(total_stmt)).scalar_one())

            rows_stmt = (
                select(AuditEventModel)
                .where(*base_filter)
                .order_by(AuditEventModel.emitted_at, AuditEventModel.audit_event_id)
                .limit(limit)
            )
            models = (await session.execute(rows_stmt)).scalars().all()
            events = tuple(self._to_event(model) for model in models)
            return AuditQueryResult(total=total, events=events)

    async def count_by_action(
        self,
        *,
        tenant_id: str,
        since: datetime,
        until: datetime,
    ) -> dict[str, int]:
        """Aggregate per-action counts inside `[since, until]` for the tenant."""
        stmt = (
            select(AuditEventModel.action, func.count())
            .where(
                AuditEventModel.tenant_id == tenant_id,
                AuditEventModel.emitted_at >= since,
                AuditEventModel.emitted_at <= until,
            )
            .group_by(AuditEventModel.action)
        )
        async with self._session_factory() as session:
            rows = (await session.execute(stmt)).all()
            return {action: int(count) for action, count in rows}

    # ----------------------------- internals ---------------------------------

    @staticmethod
    def _row_dict(*, tenant_id: str, event: AuditEvent) -> dict[str, Any]:
        return {
            "tenant_id": tenant_id,
            "correlation_id": event.correlation_id,
            "agent_id": event.agent_id,
            "action": event.action,
            "payload": event.payload,
            "previous_hash": event.previous_hash,
            "entry_hash": event.entry_hash,
            "emitted_at": event.emitted_at,
            "source": event.source,
        }

    @staticmethod
    def _to_event(model: AuditEventModel) -> AuditEvent:
        return AuditEvent(
            tenant_id=model.tenant_id,
            correlation_id=model.correlation_id,
            agent_id=model.agent_id,
            action=model.action,
            payload=dict(model.payload),
            previous_hash=model.previous_hash,
            entry_hash=model.entry_hash,
            emitted_at=model.emitted_at,
            source=model.source,
        )

    @staticmethod
    def _base_filter(
        *,
        tenant_id: str,
        since: datetime | None,
        until: datetime | None,
        action: str | None,
        agent_id: str | None,
        correlation_id: str | None,
    ) -> list[Any]:
        clauses: list[Any] = [AuditEventModel.tenant_id == tenant_id]
        if since is not None:
            clauses.append(AuditEventModel.emitted_at >= since)
        if until is not None:
            clauses.append(AuditEventModel.emitted_at <= until)
        if action is not None:
            clauses.append(AuditEventModel.action == action)
        if agent_id is not None:
            clauses.append(AuditEventModel.agent_id == agent_id)
        if correlation_id is not None:
            clauses.append(AuditEventModel.correlation_id == correlation_id)
        return clauses


__all__ = ["AuditStore"]
