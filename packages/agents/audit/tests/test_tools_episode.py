"""Tests for `audit.tools.episode_reader` (F.6 Task 7).

Production contract:

- Async wrapper per ADR-005 — querying SQLAlchemy is already async, no
  `asyncio.to_thread` needed.
- Reads from F.5's `episodes` table — every agent run event that landed
  via `EpisodicStore.append_event` is surfaced through this ingest as
  an `AuditEvent`. The episodes table is **not** chain-structured in
  F.5 (the chain lives in `charter.audit.AuditLog`'s jsonl files), so
  F.6 computes each event's `entry_hash` deterministically and roots
  the chain at `GENESIS_HASH`. The Task-8 verifier treats `source =
  memory:*` events with the `sequential=False` flag — per-entry hash
  recompute, no chain-link enforcement.
- Stamps `source = "memory:<tenant_id>"`.
- Filters by `tenant_id` (always) and optionally by `since` / `until`.
- Tolerates an episode whose row data fails AuditEvent validation
  (e.g. correlation_id too long) by dropping silently, same forgiveness
  posture as the jsonl reader.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from audit.tools.episode_reader import episode_audit_read
from charter.audit import GENESIS_HASH
from charter.memory.episodic import EpisodicStore
from charter.memory.models import Base
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def episodic(
    session_factory: async_sessionmaker[AsyncSession],
) -> EpisodicStore:
    return EpisodicStore(session_factory)


_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"


# ---------------------------- happy path -------------------------------


@pytest.mark.asyncio
async def test_episode_audit_read_returns_tuple_of_audit_events(
    episodic: EpisodicStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    await episodic.append_event(
        tenant_id=_TENANT_A,
        correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        agent_id="cloud_posture",
        action="finding.created",
        payload={"finding_id": "F-1"},
    )

    events = await episode_audit_read(session_factory=session_factory, tenant_id=_TENANT_A)
    assert isinstance(events, tuple)
    assert len(events) == 1
    e = events[0]
    assert e.tenant_id == _TENANT_A
    assert e.correlation_id == "01J7M3X9Z1K8RPVQNH2T8DBHFZ"
    assert e.agent_id == "cloud_posture"
    assert e.action == "finding.created"
    assert e.payload == {"finding_id": "F-1"}


@pytest.mark.asyncio
async def test_episode_audit_read_stamps_memory_source_tag(
    episodic: EpisodicStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    await episodic.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={},
    )

    events = await episode_audit_read(session_factory=session_factory, tenant_id=_TENANT_A)
    assert events[0].source == f"memory:{_TENANT_A}"


@pytest.mark.asyncio
async def test_episode_audit_read_chains_from_genesis(
    episodic: EpisodicStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The episodes table isn't chain-structured in F.5; F.6 roots each
    event at `GENESIS_HASH` and computes per-event hashes deterministically.
    """
    await episodic.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={},
    )
    events = await episode_audit_read(session_factory=session_factory, tenant_id=_TENANT_A)
    assert events[0].previous_hash == GENESIS_HASH
    # entry_hash is a real 64-char hex SHA-256
    assert len(events[0].entry_hash) == 64


@pytest.mark.asyncio
async def test_episode_audit_read_hashes_are_deterministic(
    episodic: EpisodicStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Same episode → same entry_hash across two reads."""
    await episodic.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={"k": "v"},
    )
    first = await episode_audit_read(session_factory=session_factory, tenant_id=_TENANT_A)
    second = await episode_audit_read(session_factory=session_factory, tenant_id=_TENANT_A)
    assert first == second


# ---------------------------- ordering ---------------------------------


@pytest.mark.asyncio
async def test_episode_audit_read_orders_by_emitted_at_ascending(
    episodic: EpisodicStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    for i in range(3):
        await episodic.append_event(
            tenant_id=_TENANT_A,
            correlation_id=f"c{i}",
            agent_id="a",
            action=f"event.{i}",
            payload={"i": i},
        )

    events = await episode_audit_read(session_factory=session_factory, tenant_id=_TENANT_A)
    timestamps = [e.emitted_at for e in events]
    assert timestamps == sorted(timestamps)


# ---------------------------- tenant isolation -------------------------


@pytest.mark.asyncio
async def test_episode_audit_read_is_tenant_scoped(
    episodic: EpisodicStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    await episodic.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={"who": "A"},
    )
    await episodic.append_event(
        tenant_id=_TENANT_B,
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={"who": "B"},
    )

    a_only = await episode_audit_read(session_factory=session_factory, tenant_id=_TENANT_A)
    assert len(a_only) == 1
    assert a_only[0].payload == {"who": "A"}


# ---------------------------- time-range filter ------------------------


@pytest.mark.asyncio
async def test_episode_audit_read_filters_by_time_range(
    episodic: EpisodicStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    # Insert three events; the EpisodicStore stamps `emitted_at` with
    # `datetime.now(UTC)` so they're all near-now. We pass a wide window
    # that should match all, and a narrow past window that should match none.
    for i in range(3):
        await episodic.append_event(
            tenant_id=_TENANT_A,
            correlation_id=f"c{i}",
            agent_id="a",
            action="x",
            payload={},
        )

    wide = await episode_audit_read(
        session_factory=session_factory,
        tenant_id=_TENANT_A,
        since=datetime(2020, 1, 1, tzinfo=UTC),
        until=datetime.now(UTC) + timedelta(hours=1),
    )
    assert len(wide) == 3

    past = await episode_audit_read(
        session_factory=session_factory,
        tenant_id=_TENANT_A,
        since=datetime(2020, 1, 1, tzinfo=UTC),
        until=datetime(2020, 1, 2, tzinfo=UTC),
    )
    assert past == ()


# ---------------------------- empty ------------------------------------


@pytest.mark.asyncio
async def test_episode_audit_read_empty_returns_empty_tuple(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    events = await episode_audit_read(session_factory=session_factory, tenant_id=_TENANT_A)
    assert events == ()
