"""Tests for GET /v1/posture (Endpoint 4 — serves the posture rollup)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager

import pytest
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from fastapi.testclient import TestClient
from read_api.app import app
from read_api.deps import get_store
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@asynccontextmanager
async def _in_memory_store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            engine, expire_on_commit=False
        )
        yield SemanticStore(factory)
    finally:
        await engine.dispose()


@asynccontextmanager
async def _seeded_store() -> AsyncIterator[SemanticStore]:
    async with _in_memory_store() as store:
        await store.upsert_entity(
            tenant_id="acme",
            entity_type="cloud_resource",
            external_id="arn:aws:ecs:us-east-1:1:svc/web",
            properties={"kind": "ecs-service", "is_public": True},
        )
        await store.upsert_entity(
            tenant_id="acme",
            entity_type="cve_finding",
            external_id="CVE-2024-0001",
            properties={"severity": "HIGH", "kev": False},
        )
        # Different tenant — its posture must not include acme's data.
        await store.upsert_entity(
            tenant_id="other",
            entity_type="cloud_resource",
            external_id="arn:aws:s3:::other",
            properties={"kind": "s3-bucket"},
        )
        yield store


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    loop = asyncio.new_event_loop()
    ctx = _seeded_store()
    store = loop.run_until_complete(ctx.__aenter__())
    app.dependency_overrides[get_store] = lambda: store
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        loop.run_until_complete(ctx.__aexit__(None, None, None))
        loop.close()


_KEYS = {
    "coverage",
    "severity_distribution",
    "by_domain",
    "by_path_type",
    "exposure_funnel",
    "inventory_counts",
    "totals",
    "top_paths",
}


def test_posture_returns_full_board_shape(client: TestClient) -> None:
    resp = client.get("/v1/posture", headers={"X-Tenant-Id": "acme"})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert set(data) >= _KEYS
    assert data["inventory_counts"].get("cloud_resource") == 1
    assert data["totals"]["findings"] == 1  # the one CVE
    assert "domain_pct" in data["coverage"]


def test_posture_is_tenant_scoped(client: TestClient) -> None:
    data = client.get("/v1/posture", headers={"X-Tenant-Id": "other"}).json()["data"]
    assert data["inventory_counts"].get("cloud_resource") == 1
    assert data["totals"]["findings"] == 0  # 'other' has no CVE


def test_posture_domain_filter(client: TestClient) -> None:
    data = client.get("/v1/posture?domain=vulnerability", headers={"X-Tenant-Id": "acme"}).json()[
        "data"
    ]
    assert all(row["domain"] == "vulnerability" for row in data["by_domain"])
