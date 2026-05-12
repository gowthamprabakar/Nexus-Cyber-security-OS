"""Tests for `investigation.tools.audit_trail` (D.7 Task 3).

The F.6 consumer. Wraps `audit.store.AuditStore.query` as an
async tool per ADR-005, with a fixed signature scoped to D.7's needs:
the investigation supplies tenant + time window + optional filters,
and the tool returns a tuple of `AuditEvent` shapes.

Production contract:

- `audit_trail_query(*, audit_store, tenant_id, since, until, ...)`
  returns `tuple[AuditEvent, ...]` — same shape F.6 emits.
- Per-axis filters (`action`, `agent_id`, `correlation_id`) are
  forwarded verbatim.
- The tool **does not** ingest. Pre-condition: the audit store
  already has the events (operator ran `audit-agent run` first).
- Errors from the underlying store bubble up — the tool is a thin
  wrapper, not a fault boundary.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from audit.schemas import AuditEvent
from audit.store import AuditStore
from charter.memory.models import Base
from investigation.tools.audit_trail import audit_trail_query
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def audit_store(
    session_factory: async_sessionmaker[AsyncSession],
) -> AuditStore:
    return AuditStore(session_factory)


_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"


def _event(
    *,
    seed: int,
    tenant_id: str = _TENANT_A,
    action: str = "episode_appended",
    agent_id: str = "cloud_posture",
    correlation_id: str = "01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    emitted_at: datetime | None = None,
) -> AuditEvent:
    h_prev = f"{seed:064x}"
    h_entry = f"{seed + 1:064x}"
    return AuditEvent(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        agent_id=agent_id,
        action=action,
        payload={"seed": seed},
        previous_hash=h_prev,
        entry_hash=h_entry,
        emitted_at=emitted_at or datetime.now(UTC),
        source=f"jsonl:fixture/{seed}",
    )


# ---------------------------- happy path -------------------------------


@pytest.mark.asyncio
async def test_returns_tuple_of_audit_events(audit_store: AuditStore) -> None:
    await audit_store.ingest(
        tenant_id=_TENANT_A,
        events=(_event(seed=1), _event(seed=3)),
    )

    out = await audit_trail_query(
        audit_store=audit_store,
        tenant_id=_TENANT_A,
        since=None,
        until=None,
    )
    assert isinstance(out, tuple)
    assert len(out) == 2
    assert all(isinstance(e, AuditEvent) for e in out)


@pytest.mark.asyncio
async def test_forwards_action_filter(audit_store: AuditStore) -> None:
    await audit_store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, action="episode_appended"),
            _event(seed=3, action="entity_upserted"),
        ),
    )

    out = await audit_trail_query(
        audit_store=audit_store,
        tenant_id=_TENANT_A,
        since=None,
        until=None,
        action="entity_upserted",
    )
    assert len(out) == 1
    assert out[0].action == "entity_upserted"


@pytest.mark.asyncio
async def test_forwards_agent_id_filter(audit_store: AuditStore) -> None:
    await audit_store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, agent_id="cloud_posture"),
            _event(seed=3, agent_id="runtime_threat"),
        ),
    )

    out = await audit_trail_query(
        audit_store=audit_store,
        tenant_id=_TENANT_A,
        since=None,
        until=None,
        agent_id="runtime_threat",
    )
    assert len(out) == 1
    assert out[0].agent_id == "runtime_threat"


@pytest.mark.asyncio
async def test_forwards_correlation_id_filter(audit_store: AuditStore) -> None:
    corr_a = "01J7M3X9Z1K8RPVQNH2T8DBHFZ"
    corr_b = "01J7N4Y0A2L9SQWRJK3U9ECIGA"
    await audit_store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, correlation_id=corr_a),
            _event(seed=3, correlation_id=corr_b),
        ),
    )

    out = await audit_trail_query(
        audit_store=audit_store,
        tenant_id=_TENANT_A,
        since=None,
        until=None,
        correlation_id=corr_b,
    )
    assert len(out) == 1
    assert out[0].correlation_id == corr_b


@pytest.mark.asyncio
async def test_forwards_time_window(audit_store: AuditStore) -> None:
    base = datetime(2026, 5, 1, tzinfo=UTC)
    await audit_store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, emitted_at=base),
            _event(seed=3, emitted_at=base + timedelta(days=1)),
            _event(seed=5, emitted_at=base + timedelta(days=10)),
        ),
    )

    out = await audit_trail_query(
        audit_store=audit_store,
        tenant_id=_TENANT_A,
        since=base + timedelta(hours=12),
        until=base + timedelta(days=5),
    )
    assert len(out) == 1


# ---------------------------- tenant isolation -------------------------


@pytest.mark.asyncio
async def test_tenant_isolation_pass_through(audit_store: AuditStore) -> None:
    """D.7 doesn't add its own tenant filter on top of F.6's — it trusts
    the underlying store. Confirms cross-tenant queries return only the
    requested tenant's rows.
    """
    await audit_store.ingest(
        tenant_id=_TENANT_A,
        events=(_event(seed=1, tenant_id=_TENANT_A),),
    )
    await audit_store.ingest(
        tenant_id=_TENANT_B,
        events=(_event(seed=3, tenant_id=_TENANT_B),),
    )

    a_only = await audit_trail_query(
        audit_store=audit_store, tenant_id=_TENANT_A, since=None, until=None
    )
    b_only = await audit_trail_query(
        audit_store=audit_store, tenant_id=_TENANT_B, since=None, until=None
    )
    assert len(a_only) == 1 and a_only[0].tenant_id == _TENANT_A
    assert len(b_only) == 1 and b_only[0].tenant_id == _TENANT_B


# ---------------------------- empty + limit ----------------------------


@pytest.mark.asyncio
async def test_empty_window_returns_empty_tuple(audit_store: AuditStore) -> None:
    out = await audit_trail_query(
        audit_store=audit_store,
        tenant_id=_TENANT_A,
        since=datetime(2030, 1, 1, tzinfo=UTC),
        until=datetime(2030, 1, 2, tzinfo=UTC),
    )
    assert out == ()


@pytest.mark.asyncio
async def test_limit_is_honoured(audit_store: AuditStore) -> None:
    """D.7 caps results at 500 in v0.1 to keep memory bounded during
    sub-agent fan-out. Configurable via `limit=` for advanced use.
    """
    await audit_store.ingest(
        tenant_id=_TENANT_A,
        events=tuple(_event(seed=i) for i in range(0, 20, 2)),
    )

    out = await audit_trail_query(
        audit_store=audit_store,
        tenant_id=_TENANT_A,
        since=None,
        until=None,
        limit=3,
    )
    assert len(out) == 3
