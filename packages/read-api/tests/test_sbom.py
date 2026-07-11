"""Tests for GET /v1/inventory/sbom (Endpoint 5 — SBOM packages)."""

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
async def _seeded_store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            engine, expire_on_commit=False
        )
        store = SemanticStore(factory)
        pkg = await store.upsert_entity(
            tenant_id="acme",
            entity_type="sbom_package",
            external_id="alpine:3.18#openssl",
            properties={"name": "openssl"},
        )
        cve = await store.upsert_entity(
            tenant_id="acme",
            entity_type="cve_finding",
            external_id="CVE-X",
            properties={"severity": "HIGH"},
        )
        await store.add_relationship(
            tenant_id="acme",
            src_entity_id=pkg,
            dst_entity_id=cve,
            relationship_type="VULNERABLE_TO",
            properties={},
        )
        await store.upsert_entity(
            tenant_id="acme",
            entity_type="sbom_package",
            external_id="alpine:3.18#zlib",
            properties={"name": "zlib"},
        )
        # Different tenant — must not leak.
        await store.upsert_entity(
            tenant_id="other",
            entity_type="sbom_package",
            external_id="img#leak",
            properties={"name": "leak"},
        )
        yield store
    finally:
        await engine.dispose()


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


def test_sbom_lists_packages_with_image_and_vuln_counts(client: TestClient) -> None:
    resp = client.get("/v1/inventory/sbom", headers={"X-Tenant-Id": "acme"})
    assert resp.status_code == 200
    by_name = {d["name"]: d for d in resp.json()["data"]}
    assert set(by_name) == {"openssl", "zlib"}  # tenant-scoped: 'leak' absent
    assert by_name["openssl"]["image"] == "alpine:3.18"
    assert by_name["openssl"]["vulnerabilities"] == 1
    assert by_name["zlib"]["vulnerabilities"] == 0
