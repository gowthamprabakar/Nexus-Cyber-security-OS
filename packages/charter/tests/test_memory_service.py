"""Tests for `charter.memory.service.MemoryService` (F.5 Task 9).

The facade is the single DI seam every agent uses to talk to memory.
Contract:

1. **Three stores hang off the facade as properties** — `episodic`,
   `procedural`, `semantic`. Each is constructed once at service-init
   time and reused for every session.
2. **`session(tenant_id=...)` is an async context manager** that yields
   an `AsyncSession`. On Postgres, it issues `SET LOCAL app.tenant_id
   = '<tid>'` inside the same transaction the session uses, so RLS
   policies fire correctly. On aiosqlite, the SET LOCAL is skipped
   (the variable isn't recognised) and the session yields cleanly.
3. **Embedder is wired into `append_event`** when no embedding is
   supplied — eager-embed-on-write per Q2.
4. **Audit log is wired into every store** — the facade passes its
   `audit_log` arg through, so every write emits a chained entry
   without the caller threading it in.
5. **Multi-tenant flow** doesn't leak — calling `session(tenant_id=A)`
   then `session(tenant_id=B)` produces independent sessions; entity/
   episode rows written in one don't appear in the other's queries
   (per the application-level tenant_id filter every store applies).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from charter.audit import AuditLog
from charter.memory.embedding import FakeEmbeddingProvider
from charter.memory.models import Base
from charter.memory.service import MemoryService
from charter.verifier import verify_audit_log
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


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(
        path=tmp_path / "audit.jsonl",
        agent="memory_service",
        run_id="01HV0T0000000000000000RUN1",
    )


@pytest.fixture
def service(
    session_factory: async_sessionmaker[AsyncSession],
    audit_log: AuditLog,
) -> MemoryService:
    return MemoryService(
        session_factory=session_factory,
        embedder=FakeEmbeddingProvider(dim=32),
        audit_log=audit_log,
    )


_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"


# ---------------------------- exposed stores -----------------------------


def test_service_exposes_three_stores(service: MemoryService) -> None:
    from charter.memory.episodic import EpisodicStore
    from charter.memory.procedural import ProceduralStore
    from charter.memory.semantic import SemanticStore

    assert isinstance(service.episodic, EpisodicStore)
    assert isinstance(service.procedural, ProceduralStore)
    assert isinstance(service.semantic, SemanticStore)


def test_service_stores_are_stable_singletons(service: MemoryService) -> None:
    """Repeated property access returns the same store instance."""
    assert service.episodic is service.episodic
    assert service.procedural is service.procedural
    assert service.semantic is service.semantic


# ---------------------------- session context manager --------------------


@pytest.mark.asyncio
async def test_session_yields_async_session(service: MemoryService) -> None:
    async with service.session(tenant_id=_TENANT_A) as session:
        assert isinstance(session, AsyncSession)


@pytest.mark.asyncio
async def test_session_works_across_two_tenants_without_leaking(
    service: MemoryService,
) -> None:
    """Writes through tenant A's session don't show up under tenant B."""
    async with service.session(tenant_id=_TENANT_A):
        await service.episodic.append_event(
            tenant_id=_TENANT_A,
            correlation_id="c",
            agent_id="a",
            action="x",
            payload={},
        )

    async with service.session(tenant_id=_TENANT_B):
        rows = await service.episodic.query_recent(tenant_id=_TENANT_B, limit=10)
    assert rows == []

    async with service.session(tenant_id=_TENANT_A):
        rows = await service.episodic.query_recent(tenant_id=_TENANT_A, limit=10)
    assert len(rows) == 1


# ---------------------------- embedder is wired in -----------------------


@pytest.mark.asyncio
async def test_append_event_embeds_payload_when_no_embedding_supplied(
    service: MemoryService,
) -> None:
    """`MemoryService.append_event` is the agent-facing path that runs
    the embedder before delegating to `EpisodicStore.append_event`.
    """
    eid = await service.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c",
        agent_id="a",
        action="payload-x",
        payload={"text": "interesting"},
    )

    rows = await service.episodic.query_by_correlation_id(tenant_id=_TENANT_A, correlation_id="c")
    assert rows[0].episode_id == eid
    assert rows[0].embedding is not None
    assert len(rows[0].embedding) == 32  # the fixture's embedder dim


@pytest.mark.asyncio
async def test_append_event_respects_explicit_embedding(
    service: MemoryService,
) -> None:
    """Caller-supplied embedding takes precedence over the embedder."""
    custom = [0.1] * 32
    eid = await service.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={"text": "y"},
        embedding=custom,
    )
    rows = await service.episodic.query_by_correlation_id(tenant_id=_TENANT_A, correlation_id="c")
    assert rows[0].episode_id == eid
    assert rows[0].embedding == custom


# ---------------------------- audit log threads through -----------------


@pytest.mark.asyncio
async def test_writes_through_service_emit_chained_audit_entries(
    service: MemoryService,
    audit_log: AuditLog,
) -> None:
    await service.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={"text": "anything"},
    )
    await service.procedural.publish_version(tenant_id=_TENANT_A, path="rem.x", body={})

    result = verify_audit_log(audit_log.path)
    assert result.valid
    assert result.entries_checked == 2


# ---------------------------- service without audit_log -----------------


@pytest.mark.asyncio
async def test_service_without_audit_log_runs_silently(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    svc = MemoryService(
        session_factory=session_factory,
        embedder=FakeEmbeddingProvider(dim=8),
    )
    eid = await svc.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={"text": "ok"},
    )
    assert eid > 0
