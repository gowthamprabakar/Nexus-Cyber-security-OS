"""Tests for the vulnerabilities endpoints (Endpoints 2 & 3)."""

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
        res = await store.upsert_entity(
            tenant_id="acme",
            entity_type="cloud_resource",
            external_id="img:1.0",
            properties={"kind": "container-image", "is_public": True},
        )
        cve1 = await store.upsert_entity(
            tenant_id="acme",
            entity_type="cve_finding",
            external_id="CVE-2024-0001",
            properties={
                "severity": "CRITICAL",
                "kev": True,
                "epss_score": 0.94,
                "cvss_v3_score": 9.8,
                "cwe": ["CWE-120"],
                "description": "buffer overflow",
            },
        )
        cve2 = await store.upsert_entity(
            tenant_id="acme",
            entity_type="cve_finding",
            external_id="CVE-2024-0002",
            properties={"severity": "HIGH", "kev": False},
        )
        await store.add_relationship(
            tenant_id="acme",
            src_entity_id=res,
            dst_entity_id=cve1,
            relationship_type="VULNERABLE_TO",
            properties={
                "package": "openssl",
                "installed_version": "1.1.1",
                "fix_version": "1.1.1w",
            },
        )
        await store.add_relationship(
            tenant_id="acme",
            src_entity_id=res,
            dst_entity_id=cve2,
            relationship_type="VULNERABLE_TO",
            properties={"package": "spring", "installed_version": "5.0", "fix_version": ""},
        )
        # Different tenant — must never leak into acme queries.
        ores = await store.upsert_entity(
            tenant_id="other",
            entity_type="cloud_resource",
            external_id="other-img",
            properties={"kind": "container-image"},
        )
        ocve = await store.upsert_entity(
            tenant_id="other",
            entity_type="cve_finding",
            external_id="CVE-OTHER",
            properties={"severity": "LOW", "kev": False},
        )
        await store.add_relationship(
            tenant_id="other",
            src_entity_id=ores,
            dst_entity_id=ocve,
            relationship_type="VULNERABLE_TO",
            properties={},
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


def test_list_returns_tenant_findings_with_fields(client: TestClient) -> None:
    resp = client.get("/v1/findings/vulnerabilities", headers={"X-Tenant-Id": "acme"})
    assert resp.status_code == 200
    data = resp.json()["data"]
    ids = {d["cve_id"] for d in data}
    assert ids == {"CVE-2024-0001", "CVE-2024-0002"}
    assert "CVE-OTHER" not in ids  # tenant scoping
    row = next(d for d in data if d["cve_id"] == "CVE-2024-0001")
    assert row["severity"] == "CRITICAL"
    assert row["kev"] is True
    assert row["epss"] == 0.94
    assert row["resource"] == "img:1.0"
    assert row["component"] == "openssl"
    assert row["fix_version"] == "1.1.1w"
    assert row["status"] == "open"


def test_severity_and_kev_filters(client: TestClient) -> None:
    kev = client.get("/v1/findings/vulnerabilities?kev=true", headers={"X-Tenant-Id": "acme"})
    assert {d["cve_id"] for d in kev.json()["data"]} == {"CVE-2024-0001"}
    high = client.get("/v1/findings/vulnerabilities?severity=high", headers={"X-Tenant-Id": "acme"})
    assert {d["cve_id"] for d in high.json()["data"]} == {"CVE-2024-0002"}


def test_detail_returns_enriched_fields_and_advisory(client: TestClient) -> None:
    resp = client.get("/v1/findings/vulnerabilities/CVE-2024-0001", headers={"X-Tenant-Id": "acme"})
    assert resp.status_code == 200
    d = resp.json()["data"]
    assert d["cvss_v3_score"] == 9.8
    assert d["cwe"] == ["CWE-120"]
    assert d["description"] == "buffer overflow"
    assert d["affected_resources"] == ["img:1.0"]
    assert d["remediation"]["tier"] == "advisory"
    assert "1.1.1w" in d["remediation"]["advice"]


def test_detail_unknown_cve_is_404(client: TestClient) -> None:
    resp = client.get("/v1/findings/vulnerabilities/CVE-NOPE", headers={"X-Tenant-Id": "acme"})
    assert resp.status_code == 404


def test_catalog_dedupes_ranks_and_scopes(client: TestClient) -> None:
    resp = client.get("/v1/findings/catalog", headers={"X-Tenant-Id": "acme"})
    assert resp.status_code == 200
    data = resp.json()["data"]
    ids = [d["cve_id"] for d in data]
    assert ids == ["CVE-2024-0001", "CVE-2024-0002"]  # KEV-first ranking
    assert "CVE-OTHER" not in ids  # tenant scoping
    top = data[0]
    assert top["kev"] is True
    assert top["affected_resources"] == 1  # img:1.0


def test_catalog_kev_filter(client: TestClient) -> None:
    resp = client.get("/v1/findings/catalog?kev=true", headers={"X-Tenant-Id": "acme"})
    assert {d["cve_id"] for d in resp.json()["data"]} == {"CVE-2024-0001"}
