"""Tests for `charter.memory.episodic.EpisodicStore` (F.5 Task 3).

Eight assertions cover the production contract:

1. `append_event` round-trips against aiosqlite + returns the row's primary key
2. `query_by_correlation_id` groups every event sharing a correlation_id
3. cross-tenant isolation: a tenant only sees its own rows
4. payload + embedding round-trip without truncation (JSON list[float])
5. `query_recent` paginates DESC by emitted_at with a limit
6. `search_similar` runs without raising on aiosqlite (pgvector ANN gated
   behind the live-Postgres integration test in Task 10) and returns an
   empty list rather than raising the missing-operator error
7. append + downstream queries inside a single session work with the
   async_sessionmaker correctly
8. session_factory is the only injection seam — no global state.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory.episodic import EpisodicStore
from charter.memory.models import Base
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Fresh in-memory aiosqlite per test for full isolation."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def store(
    session_factory: async_sessionmaker[AsyncSession],
) -> EpisodicStore:
    return EpisodicStore(session_factory)


# ---------------------------- append + query round-trip ------------------


@pytest.mark.asyncio
async def test_append_event_returns_positive_episode_id(store: EpisodicStore) -> None:
    eid = await store.append_event(
        tenant_id="01HV0T0000000000000000TEN1",
        correlation_id="corr-abc",
        agent_id="cloud_posture",
        action="finding.created",
        payload={"finding_id": "F-1", "severity": "high"},
    )
    assert isinstance(eid, int)
    assert eid > 0


@pytest.mark.asyncio
async def test_query_by_correlation_id_returns_every_event(store: EpisodicStore) -> None:
    tenant = "01HV0T0000000000000000TEN1"
    for i in range(3):
        await store.append_event(
            tenant_id=tenant,
            correlation_id="corr-xyz",
            agent_id="runtime_threat",
            action=f"event.{i}",
            payload={"i": i},
        )
    # noise on a different correlation_id — must not bleed in.
    await store.append_event(
        tenant_id=tenant,
        correlation_id="other",
        agent_id="x",
        action="x",
        payload={},
    )

    rows = await store.query_by_correlation_id(tenant_id=tenant, correlation_id="corr-xyz")
    assert len(rows) == 3
    actions = {r.action for r in rows}
    assert actions == {"event.0", "event.1", "event.2"}


# ---------------------------- tenant isolation ---------------------------


@pytest.mark.asyncio
async def test_query_by_correlation_id_is_tenant_scoped(store: EpisodicStore) -> None:
    await store.append_event(
        tenant_id="01HV0T0000000000000000TEN1",
        correlation_id="shared-corr",
        agent_id="a",
        action="x",
        payload={},
    )
    await store.append_event(
        tenant_id="01HV0T0000000000000000TEN2",
        correlation_id="shared-corr",
        agent_id="a",
        action="y",
        payload={},
    )

    t1_rows = await store.query_by_correlation_id(
        tenant_id="01HV0T0000000000000000TEN1", correlation_id="shared-corr"
    )
    t2_rows = await store.query_by_correlation_id(
        tenant_id="01HV0T0000000000000000TEN2", correlation_id="shared-corr"
    )
    assert len(t1_rows) == 1 and t1_rows[0].action == "x"
    assert len(t2_rows) == 1 and t2_rows[0].action == "y"


# ---------------------------- payload + embedding round-trip -------------


@pytest.mark.asyncio
async def test_payload_and_embedding_round_trip(store: EpisodicStore) -> None:
    payload = {
        "deeply": {"nested": [1, 2, {"k": "v"}]},
        "unicode": "🛡️ — em-dash",
        "null": None,
        "bool": True,
    }
    embedding = [0.1, 0.2, -0.3, 0.4]
    eid = await store.append_event(
        tenant_id="01HV0T0000000000000000TEN1",
        correlation_id="c",
        agent_id="a",
        action="x",
        payload=payload,
        embedding=embedding,
    )

    rows = await store.query_by_correlation_id(
        tenant_id="01HV0T0000000000000000TEN1", correlation_id="c"
    )
    assert len(rows) == 1
    assert rows[0].episode_id == eid
    assert rows[0].payload == payload
    assert rows[0].embedding == embedding


@pytest.mark.asyncio
async def test_embedding_defaults_to_none(store: EpisodicStore) -> None:
    eid = await store.append_event(
        tenant_id="01HV0T0000000000000000TEN1",
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={},
    )
    rows = await store.query_by_correlation_id(
        tenant_id="01HV0T0000000000000000TEN1", correlation_id="c"
    )
    assert rows[0].episode_id == eid
    assert rows[0].embedding is None


# ---------------------------- query_recent / pagination ------------------


@pytest.mark.asyncio
async def test_query_recent_returns_most_recent_first_with_limit(
    store: EpisodicStore,
) -> None:
    tenant = "01HV0T0000000000000000TEN1"
    for i in range(5):
        await store.append_event(
            tenant_id=tenant,
            correlation_id=f"c{i}",
            agent_id="a",
            action=f"action.{i}",
            payload={"i": i},
        )

    rows = await store.query_recent(tenant_id=tenant, limit=3)
    assert len(rows) == 3
    # autoincrement → larger episode_id is more recent.
    ids = [r.episode_id for r in rows]
    assert ids == sorted(ids, reverse=True)


@pytest.mark.asyncio
async def test_query_recent_is_tenant_scoped(store: EpisodicStore) -> None:
    for tenant in ("01HV0T0000000000000000TEN1", "01HV0T0000000000000000TEN2"):
        await store.append_event(
            tenant_id=tenant,
            correlation_id="c",
            agent_id="a",
            action="x",
            payload={},
        )
    rows = await store.query_recent(tenant_id="01HV0T0000000000000000TEN1", limit=10)
    assert len(rows) == 1
    assert rows[0].tenant_id == "01HV0T0000000000000000TEN1"


# ---------------------------- search_similar (graceful on sqlite) --------


@pytest.mark.asyncio
async def test_search_similar_returns_empty_on_non_postgres(
    store: EpisodicStore,
) -> None:
    """pgvector ANN is Postgres-only; on aiosqlite the call must not raise
    and must return [] so calling code can degrade gracefully. The live
    integration test (Task 10) verifies real ANN ranking against Postgres.
    """
    await store.append_event(
        tenant_id="01HV0T0000000000000000TEN1",
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={},
        embedding=[0.1, 0.2, 0.3],
    )
    rows = await store.search_similar(
        tenant_id="01HV0T0000000000000000TEN1",
        embedding=[0.1, 0.2, 0.3],
        top_k=5,
    )
    assert rows == []


# ---------------------------- session_factory is the only seam -----------


def test_episodic_store_takes_session_factory_only(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Confirms the injection seam — no env vars, no globals."""
    store = EpisodicStore(session_factory)
    assert store._session_factory is session_factory
