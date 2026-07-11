"""Tests for GET /v1/inventory/container-images (Endpoint 6 — image rollup)."""

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
        # Image with one package (CONTAINS_PACKAGE) and one direct CVE (VULNERABLE_TO).
        img = await store.upsert_entity(
            tenant_id="acme",
            entity_type="cloud_resource",
            external_id="alpine:3.18",
            properties={"kind": "container-image"},
        )
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
            src_entity_id=img,
            dst_entity_id=pkg,
            relationship_type="CONTAINS_PACKAGE",
            properties={},
        )
        await store.add_relationship(
            tenant_id="acme",
            src_entity_id=img,
            dst_entity_id=cve,
            relationship_type="VULNERABLE_TO",
            properties={},
        )
        # Image with no packages or CVEs → 0/0.
        await store.upsert_entity(
            tenant_id="acme",
            entity_type="cloud_resource",
            external_id="scratch:latest",
            properties={"kind": "container-image"},
        )
        # Non-image resource — must be excluded.
        await store.upsert_entity(
            tenant_id="acme",
            entity_type="cloud_resource",
            external_id="arn:aws:ec2:::i-1",
            properties={"kind": "ec2-instance"},
        )
        # Different tenant — must not leak.
        await store.upsert_entity(
            tenant_id="other",
            entity_type="cloud_resource",
            external_id="leak:latest",
            properties={"kind": "container-image"},
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


def test_lists_images_with_package_and_vuln_counts(client: TestClient) -> None:
    resp = client.get("/v1/inventory/container-images", headers={"X-Tenant-Id": "acme"})
    assert resp.status_code == 200
    by_id = {d["id"]: d for d in resp.json()["data"]}
    # Only images, tenant-scoped: the ec2 resource and 'other' tenant image are absent.
    assert set(by_id) == {"alpine:3.18", "scratch:latest"}
    assert by_id["alpine:3.18"]["packages"] == 1
    assert by_id["alpine:3.18"]["vulnerabilities"] == 1
    assert by_id["scratch:latest"]["packages"] == 0
    assert by_id["scratch:latest"]["vulnerabilities"] == 0


def test_foreign_tenant_sees_nothing(client: TestClient) -> None:
    resp = client.get("/v1/inventory/container-images", headers={"X-Tenant-Id": "ghost"})
    assert resp.status_code == 200
    assert resp.json()["data"] == []
