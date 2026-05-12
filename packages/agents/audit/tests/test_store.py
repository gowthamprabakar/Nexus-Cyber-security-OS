"""Tests for `audit.store.AuditStore` (F.6 Task 5).

Production contract:

- `ingest(*, tenant_id, events)` is **idempotent on `(tenant_id, entry_hash)`** —
  re-running an ingest over the same `audit.jsonl` file produces a no-op
  rather than duplicates. Returns the count of newly inserted events.
- `query(*, tenant_id, ...)` filters by any subset of:
  `since`, `until`, `action`, `agent_id`, `correlation_id`. Returns
  results ordered by `emitted_at` ascending. Limit is honoured.
- `count_by_action(*, tenant_id, since, until)` returns a dict keyed by
  action with raw counts inside the window.
- Tenant isolation: application-side `WHERE tenant_id = ?` is the
  secondary defence on top of the Task-3 RLS policy (live integration
  test in Task 16 exercises the RLS itself).
- Output type is the pydantic `AuditQueryResult` from Task 4 — wire
  shape is stable.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from audit.schemas import AuditEvent
from audit.store import AuditStore
from charter.memory.models import Base
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def store(
    session_factory: async_sessionmaker[AsyncSession],
) -> AuditStore:
    return AuditStore(session_factory)


_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"
_HEX = "0123456789abcdef"


def _hash(seed: int) -> str:
    """Stable hex64 derived from `seed` — deterministic, unique per seed."""
    rendered = f"{seed:064x}"
    return rendered


def _event(
    *,
    seed: int,
    tenant_id: str = _TENANT_A,
    correlation_id: str = "01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    action: str = "episode_appended",
    agent_id: str = "cloud_posture",
    emitted_at: datetime | None = None,
) -> AuditEvent:
    previous = _hash(seed)
    entry = _hash(seed + 1)
    return AuditEvent(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        agent_id=agent_id,
        action=action,
        payload={"seed": seed},
        previous_hash=previous,
        entry_hash=entry,
        emitted_at=emitted_at or datetime.now(UTC),
        source=f"jsonl:fixture/{seed}",
    )


# ---------------------------- ingest happy path -------------------------


@pytest.mark.asyncio
async def test_ingest_returns_count_of_new_events(store: AuditStore) -> None:
    events = (_event(seed=1), _event(seed=3), _event(seed=5))
    inserted = await store.ingest(tenant_id=_TENANT_A, events=events)
    assert inserted == 3


@pytest.mark.asyncio
async def test_ingest_empty_iterable_is_noop(store: AuditStore) -> None:
    inserted = await store.ingest(tenant_id=_TENANT_A, events=())
    assert inserted == 0


# ---------------------------- idempotency contract ----------------------


@pytest.mark.asyncio
async def test_re_ingest_same_events_is_idempotent(store: AuditStore) -> None:
    """The (tenant_id, entry_hash) UNIQUE constraint (F.6 Task 2) ensures
    that re-ingesting the same audit.jsonl file doesn't duplicate rows.
    """
    events = (_event(seed=1), _event(seed=3))
    first = await store.ingest(tenant_id=_TENANT_A, events=events)
    second = await store.ingest(tenant_id=_TENANT_A, events=events)
    assert first == 2
    assert second == 0

    result = await store.query(tenant_id=_TENANT_A)
    assert result.total == 2


@pytest.mark.asyncio
async def test_partial_re_ingest_only_inserts_new(store: AuditStore) -> None:
    """Half-overlap: re-ingest carries some already-known and some new
    events. Only the new ones land; the duplicates are dropped silently.
    """
    await store.ingest(tenant_id=_TENANT_A, events=(_event(seed=1),))
    inserted = await store.ingest(
        tenant_id=_TENANT_A,
        events=(_event(seed=1), _event(seed=3)),  # seed=1 is a re-ingest
    )
    assert inserted == 1


# ---------------------------- query filters -----------------------------


@pytest.mark.asyncio
async def test_query_orders_by_emitted_at_ascending(store: AuditStore) -> None:
    base = datetime(2026, 5, 1, tzinfo=UTC)
    await store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=5, emitted_at=base + timedelta(days=2)),
            _event(seed=1, emitted_at=base + timedelta(days=0)),
            _event(seed=3, emitted_at=base + timedelta(days=1)),
        ),
    )
    result = await store.query(tenant_id=_TENANT_A)
    actions = [e.emitted_at for e in result.events]
    assert actions == sorted(actions)


@pytest.mark.asyncio
async def test_query_filters_by_action(store: AuditStore) -> None:
    await store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, action="episode_appended"),
            _event(seed=3, action="entity_upserted"),
            _event(seed=5, action="episode_appended"),
        ),
    )
    result = await store.query(tenant_id=_TENANT_A, action="episode_appended")
    assert result.total == 2
    assert all(e.action == "episode_appended" for e in result.events)


@pytest.mark.asyncio
async def test_query_filters_by_agent_id(store: AuditStore) -> None:
    await store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, agent_id="cloud_posture"),
            _event(seed=3, agent_id="runtime_threat"),
        ),
    )
    result = await store.query(tenant_id=_TENANT_A, agent_id="runtime_threat")
    assert result.total == 1
    assert result.events[0].agent_id == "runtime_threat"


@pytest.mark.asyncio
async def test_query_filters_by_correlation_id(store: AuditStore) -> None:
    await store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ"),
            _event(seed=3, correlation_id="01J7N4Y0A2L9SQWRJK3U9ECIGA"),
        ),
    )
    result = await store.query(tenant_id=_TENANT_A, correlation_id="01J7N4Y0A2L9SQWRJK3U9ECIGA")
    assert result.total == 1


@pytest.mark.asyncio
async def test_query_filters_by_time_window(store: AuditStore) -> None:
    base = datetime(2026, 5, 1, tzinfo=UTC)
    await store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, emitted_at=base),
            _event(seed=3, emitted_at=base + timedelta(days=1)),
            _event(seed=5, emitted_at=base + timedelta(days=10)),
        ),
    )
    result = await store.query(
        tenant_id=_TENANT_A,
        since=base + timedelta(hours=12),
        until=base + timedelta(days=5),
    )
    assert result.total == 1


@pytest.mark.asyncio
async def test_query_limit_is_honoured(store: AuditStore) -> None:
    await store.ingest(
        tenant_id=_TENANT_A,
        events=tuple(_event(seed=i) for i in range(0, 20, 2)),
    )
    result = await store.query(tenant_id=_TENANT_A, limit=3)
    assert result.total == 10
    assert len(result.events) == 3


@pytest.mark.asyncio
async def test_query_combines_multiple_filters(store: AuditStore) -> None:
    base = datetime(2026, 5, 1, tzinfo=UTC)
    await store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, action="episode_appended", agent_id="x", emitted_at=base),
            _event(seed=3, action="episode_appended", agent_id="y", emitted_at=base),
            _event(seed=5, action="entity_upserted", agent_id="x", emitted_at=base),
        ),
    )
    result = await store.query(tenant_id=_TENANT_A, action="episode_appended", agent_id="x")
    assert result.total == 1
    assert result.events[0].action == "episode_appended"
    assert result.events[0].agent_id == "x"


# ---------------------------- tenant isolation --------------------------


@pytest.mark.asyncio
async def test_query_is_tenant_scoped(store: AuditStore) -> None:
    await store.ingest(tenant_id=_TENANT_A, events=(_event(seed=1, tenant_id=_TENANT_A),))
    await store.ingest(tenant_id=_TENANT_B, events=(_event(seed=3, tenant_id=_TENANT_B),))
    a_only = await store.query(tenant_id=_TENANT_A)
    b_only = await store.query(tenant_id=_TENANT_B)
    assert a_only.total == 1
    assert b_only.total == 1
    assert a_only.events[0].tenant_id == _TENANT_A
    assert b_only.events[0].tenant_id == _TENANT_B


# ---------------------------- count_by_action ---------------------------


@pytest.mark.asyncio
async def test_count_by_action_returns_window_counts(store: AuditStore) -> None:
    base = datetime(2026, 5, 1, tzinfo=UTC)
    await store.ingest(
        tenant_id=_TENANT_A,
        events=(
            _event(seed=1, action="episode_appended", emitted_at=base),
            _event(seed=3, action="episode_appended", emitted_at=base + timedelta(hours=1)),
            _event(seed=5, action="entity_upserted", emitted_at=base + timedelta(hours=2)),
            # outside the window:
            _event(seed=7, action="episode_appended", emitted_at=base + timedelta(days=10)),
        ),
    )
    counts = await store.count_by_action(
        tenant_id=_TENANT_A, since=base, until=base + timedelta(hours=6)
    )
    assert counts == {"episode_appended": 2, "entity_upserted": 1}
