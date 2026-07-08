"""Tests for GET /v1/inventory/cloud-resources (Endpoint 1)."""

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
    """Minimal in-memory SemanticStore — mirrors fleet_testkit.store without boto3 dep."""
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
    """Yield a SemanticStore pre-seeded with test cloud-resource nodes."""
    async with _in_memory_store() as store:
        # Node 1: public AWS ECS service — tenant "acme"
        await store.upsert_entity(
            tenant_id="acme",
            entity_type="cloud_resource",
            external_id="arn:aws:ecs:us-east-1:123456789012:service/web",
            properties={"kind": "ecs-service", "is_public": True, "region": "us-east-1"},
        )
        # Node 2: private Azure container group — tenant "acme"
        await store.upsert_entity(
            tenant_id="acme",
            entity_type="cloud_resource",
            external_id="azure-container-group/my-group",
            properties={"kind": "azure-container-group", "is_public": False},
        )
        # Node 3: GCP Cloud Run — tenant "acme"
        await store.upsert_entity(
            tenant_id="acme",
            entity_type="cloud_resource",
            external_id="gcp-run/my-service",
            properties={
                "kind": "gcp-cloud-run-service",
                "is_public": True,
                "region": "us-central1",
            },
        )
        # Node 4: different tenant — must NOT appear in acme queries
        await store.upsert_entity(
            tenant_id="other",
            entity_type="cloud_resource",
            external_id="arn:aws:s3:::other-bucket",
            properties={"kind": "s3-bucket", "is_public": False},
        )
        yield store


@pytest.fixture()
def client_with_store() -> Generator[TestClient, None, None]:
    """TestClient backed by a fresh in-memory SemanticStore seeded with test data.

    The store's async context manager is kept alive for the full fixture scope so the
    sqlite engine (and its data) outlives each individual test call.
    """
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


def test_list_returns_200_envelope(client_with_store: TestClient) -> None:
    resp = client_with_store.get(
        "/v1/inventory/cloud-resources",
        headers={"X-Tenant-Id": "acme"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "data" in body
    assert "meta" in body
    meta = body["meta"]
    assert meta["tenant"] == "acme"
    assert "generated_at" in meta


def test_list_returns_only_tenant_nodes(client_with_store: TestClient) -> None:
    resp = client_with_store.get(
        "/v1/inventory/cloud-resources",
        headers={"X-Tenant-Id": "acme"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    # Should return 3 acme nodes, NOT the "other" tenant node
    assert len(data) == 3
    ids = {row["id"] for row in data}
    assert "arn:aws:s3:::other-bucket" not in ids


def test_field_mapping_aws(client_with_store: TestClient) -> None:
    resp = client_with_store.get(
        "/v1/inventory/cloud-resources",
        headers={"X-Tenant-Id": "acme"},
    )
    data = resp.json()["data"]
    aws_rows = [r for r in data if r["id"] == "arn:aws:ecs:us-east-1:123456789012:service/web"]
    assert len(aws_rows) == 1
    row = aws_rows[0]
    assert row["kind"] == "ecs-service"
    assert row["cloud"] == "aws"
    assert row["is_public"] is True
    assert row["region"] == "us-east-1"


def test_field_mapping_azure(client_with_store: TestClient) -> None:
    resp = client_with_store.get(
        "/v1/inventory/cloud-resources",
        headers={"X-Tenant-Id": "acme"},
    )
    data = resp.json()["data"]
    azure_rows = [r for r in data if r["id"] == "azure-container-group/my-group"]
    assert len(azure_rows) == 1
    row = azure_rows[0]
    assert row["cloud"] == "azure"
    assert row["is_public"] is False
    assert row["region"] is None


def test_field_mapping_gcp(client_with_store: TestClient) -> None:
    resp = client_with_store.get(
        "/v1/inventory/cloud-resources",
        headers={"X-Tenant-Id": "acme"},
    )
    data = resp.json()["data"]
    gcp_rows = [r for r in data if r["id"] == "gcp-run/my-service"]
    assert len(gcp_rows) == 1
    row = gcp_rows[0]
    assert row["cloud"] == "gcp"
    assert row["is_public"] is True
    assert row["region"] == "us-central1"


def test_filter_by_kind(client_with_store: TestClient) -> None:
    resp = client_with_store.get(
        "/v1/inventory/cloud-resources?kind=ecs-service",
        headers={"X-Tenant-Id": "acme"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert len(data) == 1
    assert data[0]["kind"] == "ecs-service"


def test_filter_public_true(client_with_store: TestClient) -> None:
    resp = client_with_store.get(
        "/v1/inventory/cloud-resources?public=true",
        headers={"X-Tenant-Id": "acme"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    # Only the AWS ECS and GCP Cloud Run nodes are public
    assert len(data) == 2
    assert all(r["is_public"] is True for r in data)


def test_filter_public_false(client_with_store: TestClient) -> None:
    resp = client_with_store.get(
        "/v1/inventory/cloud-resources?public=false",
        headers={"X-Tenant-Id": "acme"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert len(data) == 1
    assert data[0]["is_public"] is False


def test_pagination_cursor(client_with_store: TestClient) -> None:
    # Request limit=2 — should get first 2 of 3 nodes, next cursor=2
    resp = client_with_store.get(
        "/v1/inventory/cloud-resources?cursor=0&limit=2",
        headers={"X-Tenant-Id": "acme"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 2
    assert body["meta"]["cursor"] == 2
    assert body["meta"]["total"] == 3

    # Fetch page 2
    resp2 = client_with_store.get(
        "/v1/inventory/cloud-resources?cursor=2&limit=2",
        headers={"X-Tenant-Id": "acme"},
    )
    assert resp2.status_code == 200
    body2 = resp2.json()
    assert len(body2["data"]) == 1
    assert body2["meta"]["cursor"] is None  # no more pages


def test_default_tenant_is_dev(client_with_store: TestClient) -> None:
    # No X-Tenant-Id header → tenant defaults to "dev" → no acme data
    resp = client_with_store.get("/v1/inventory/cloud-resources")
    assert resp.status_code == 200
    body = resp.json()
    assert body["meta"]["tenant"] == "dev"
    assert body["data"] == []
