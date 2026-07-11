"""Tests for GET /v1/audit (Endpoint 9 — audit log over the F.6 chain)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from audit.schemas import AuditEvent
from audit.store import AuditStore
from charter.audit import GENESIS_HASH, _hash_entry
from charter.memory.models import Base
from fastapi.testclient import TestClient
from read_api.app import app
from read_api.deps import get_audit_store
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Audit tenant_ids are 26-char ULIDs.
_TENANT_A = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
_TENANT_B = "01BX5ZZKBKACTAV9WEVGEMMVRZ"


def _event(tenant: str, action: str, entry_hash: str) -> AuditEvent:
    return AuditEvent(
        tenant_id=tenant,
        correlation_id="corr-1",
        agent_id="audit-agent",
        action=action,
        payload={"k": "v"},
        previous_hash="0" * 64,
        entry_hash=entry_hash,
        emitted_at=datetime(2026, 1, 1, tzinfo=UTC),
        source="jsonl:/audit.jsonl",
    )


@asynccontextmanager
async def _seeded_store() -> AsyncIterator[AuditStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            engine, expire_on_commit=False
        )
        store = AuditStore(factory)
        await store.ingest(
            tenant_id=_TENANT_A,
            events=[
                _event(_TENANT_A, "entity.upserted", "a" * 64),
                _event(_TENANT_A, "relationship.added", "c" * 64),
            ],
        )
        # Different tenant — must not leak into tenant A's query.
        await store.ingest(
            tenant_id=_TENANT_B,
            events=[_event(_TENANT_B, "entity.upserted", "b" * 64)],
        )
        yield store
    finally:
        await engine.dispose()


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    loop = asyncio.new_event_loop()
    ctx = _seeded_store()
    store = loop.run_until_complete(ctx.__aenter__())
    app.dependency_overrides[get_audit_store] = lambda: store
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        loop.run_until_complete(ctx.__aexit__(None, None, None))
        loop.close()


def test_lists_tenant_audit_events(client: TestClient) -> None:
    resp = client.get("/v1/audit", headers={"X-Tenant-Id": _TENANT_A})
    assert resp.status_code == 200
    body = resp.json()
    assert body["meta"]["total"] == 2
    assert {e["action"] for e in body["data"]} == {"entity.upserted", "relationship.added"}
    row = body["data"][0]
    assert row["agent_id"] == "audit-agent"
    assert "entry_hash" not in row  # chain internals omitted from the list view


def test_tenant_scoped(client: TestClient) -> None:
    b = client.get("/v1/audit", headers={"X-Tenant-Id": _TENANT_B})
    assert b.json()["meta"]["total"] == 1
    assert {e["action"] for e in b.json()["data"]} == {"entity.upserted"}


def test_action_filter(client: TestClient) -> None:
    resp = client.get("/v1/audit?action=relationship.added", headers={"X-Tenant-Id": _TENANT_A})
    assert [e["action"] for e in resp.json()["data"]] == ["relationship.added"]


def test_absent_tenant_sees_nothing(client: TestClient) -> None:
    resp = client.get("/v1/audit", headers={"X-Tenant-Id": "01CCCCCCCCCCCCCCCCCCCCCCCC"})
    assert resp.status_code == 200
    assert resp.json()["data"] == []


# ---------------------------- chain verification ------------------------


def _chained(action: str, cid: str, ts: datetime, previous_hash: str) -> AuditEvent:
    """A real chain entry: entry_hash computed the way the producer does."""
    entry_hash = _hash_entry(
        timestamp=ts.isoformat().replace("+00:00", "Z"),
        agent="audit-agent",
        run_id=cid,
        action=action,
        payload={},
        previous_hash=previous_hash,
    )
    return AuditEvent(
        tenant_id=_TENANT_A,
        correlation_id=cid,
        agent_id="audit-agent",
        action=action,
        payload={},
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        emitted_at=ts,
        source="jsonl:/audit.jsonl",
    )


def _verify(events: tuple[AuditEvent, ...]) -> dict:
    """Ingest a chain, hit /v1/audit/verify, return the verdict payload."""
    loop = asyncio.new_event_loop()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async def _seed() -> AuditStore:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        store = AuditStore(async_sessionmaker(engine, expire_on_commit=False))
        await store.ingest(tenant_id=_TENANT_A, events=list(events))
        return store

    store = loop.run_until_complete(_seed())
    app.dependency_overrides[get_audit_store] = lambda: store
    try:
        resp = TestClient(app).get("/v1/audit/verify", headers={"X-Tenant-Id": _TENANT_A})
        assert resp.status_code == 200
        return resp.json()["data"]
    finally:
        app.dependency_overrides.clear()
        loop.run_until_complete(engine.dispose())
        loop.close()


def test_verify_valid_chain() -> None:
    """A genuine chain, ingested and queried back, verifies — the tz round-trip
    fix (#812) is what makes this pass over the store mirror.
    """
    t1 = datetime(2026, 1, 1, tzinfo=UTC)
    t2 = datetime(2026, 1, 1, 0, 1, tzinfo=UTC)
    e1 = _chained("entity.upserted", "corr-a", t1, GENESIS_HASH)
    e2 = _chained("relationship.added", "corr-b", t2, e1.entry_hash)
    data = _verify((e1, e2))
    assert data["valid"] is True
    assert data["entries_checked"] == 2
    assert data["complete"] is True
    assert data["broken_at_correlation_id"] is None


def test_verify_detects_tampering() -> None:
    """Tampering an entry's payload (leaving its stored hash) breaks the recompute."""
    t1 = datetime(2026, 1, 1, tzinfo=UTC)
    t2 = datetime(2026, 1, 1, 0, 1, tzinfo=UTC)
    e1 = _chained("entity.upserted", "corr-a", t1, GENESIS_HASH)
    good = _chained("relationship.added", "corr-b", t2, e1.entry_hash)
    tampered = good.model_copy(update={"payload": {"evil": True}})
    data = _verify((e1, tampered))
    assert data["valid"] is False
    assert data["broken_at_correlation_id"] == "corr-b"
