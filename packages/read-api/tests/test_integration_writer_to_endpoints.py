"""End-to-end contract test: the REAL vulnerability writer → graph → read endpoints.

Every other read-api test hand-seeds the graph with the node/edge vocab the endpoints
expect. This one instead drives the production ``KnowledgeGraphWriter`` (the same code
the vulnerability agent runs on Trivy output) and asserts each endpoint reflects what
the writer actually wrote. It is the guard against writer/reader field drift — the
"green-for-wrong-reason" class where a writer stamps ``epss_score`` but a reader reads
``epss``, or an edge carries ``pkg`` but the reader expects ``package``.
"""

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
from vulnerability.kg_writer import KnowledgeGraphWriter
from vulnerability.tools.trivy import TrivyResult

_TENANT = "acme"

# A realistic Trivy image scan: two CVEs on one artifact, one with a fix + full
# enrichment (CVSS/CWE/description), one without a fix.
_TRIVY = TrivyResult(
    raw_findings=[
        {
            "VulnerabilityID": "CVE-2024-0001",
            "_artifact_name": "img:1.0",
            "_class": "os-pkgs",
            "Severity": "CRITICAL",
            "PkgName": "openssl",
            "InstalledVersion": "1.1.1",
            "FixedVersion": "1.1.1w",
            "CVSS": {"nvd": {"V3Score": 9.8}},
            "CweIDs": ["CWE-120"],
            "Description": "buffer overflow",
        },
        {
            "VulnerabilityID": "CVE-2024-0002",
            "_artifact_name": "img:1.0",
            "_class": "os-pkgs",
            "Severity": "HIGH",
            "PkgName": "spring",
            "InstalledVersion": "5.0",
            "FixedVersion": "",  # no fix available
        },
    ]
)


@asynccontextmanager
async def _writer_seeded_store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            engine, expire_on_commit=False
        )
        store = SemanticStore(factory)
        writer = KnowledgeGraphWriter(store, _TENANT)
        # Direct scan path: resource → VULNERABLE_TO → CVE, with KEV + EPSS signals.
        await writer.record_scan_results(
            [_TRIVY],
            kev_cve_ids={"CVE-2024-0001"},
            epss_scores={"CVE-2024-0001": 0.94},
        )
        # Supply-chain path: image → CONTAINS_PACKAGE → package → VULNERABLE_TO → CVE.
        await writer.record_sbom_packages(
            "alpine:3.18",
            [("openssl", "CVE-2024-0001", "CRITICAL"), ("zlib", "CVE-2024-0009", "LOW")],
        )
        yield store
    finally:
        await engine.dispose()


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    loop = asyncio.new_event_loop()
    ctx = _writer_seeded_store()
    store = loop.run_until_complete(ctx.__aenter__())
    app.dependency_overrides[get_store] = lambda: store
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        loop.run_until_complete(ctx.__aexit__(None, None, None))
        loop.close()


def _get(client: TestClient, path: str) -> list | dict:
    resp = client.get(path, headers={"X-Tenant-Id": _TENANT})
    assert resp.status_code == 200, (path, resp.status_code)
    return resp.json()["data"]


def test_vulnerabilities_reflect_writer_fields(client: TestClient) -> None:
    rows = {r["cve_id"]: r for r in _get(client, "/v1/findings/vulnerabilities")}
    # Direct-scan CVEs land on the resource; SBOM-path CVEs are on packages, not here.
    assert set(rows) == {"CVE-2024-0001", "CVE-2024-0002"}
    crit = rows["CVE-2024-0001"]
    assert crit["severity"] == "CRITICAL"
    assert crit["kev"] is True  # kev_cve_ids → node.kev → reader.kev
    assert crit["epss"] == 0.94  # epss_scores → node.epss_score → reader.epss
    assert crit["resource"] == "img:1.0"  # _artifact_name → resource external_id
    assert crit["component"] == "openssl"  # PkgName → edge.package → reader.component
    assert crit["fix_version"] == "1.1.1w"  # FixedVersion → edge.fix_version


def test_detail_reflects_enrichment(client: TestClient) -> None:
    detail = _get(client, "/v1/findings/vulnerabilities/CVE-2024-0001")
    assert detail["cvss_v3_score"] == 9.8  # CVSS.nvd.V3Score → node.cvss_v3_score
    assert detail["cwe"] == ["CWE-120"]  # CweIDs → node.cwe
    assert detail["description"] == "buffer overflow"
    assert detail["affected_resources"] == ["img:1.0"]
    assert "1.1.1w" in detail["remediation"]["advice"]


def test_catalog_dedups_and_counts_direct_resources(client: TestClient) -> None:
    rows = {r["cve_id"]: r for r in _get(client, "/v1/findings/catalog")}
    # All CVE nodes appear (incl. the SBOM-only one); direct-scan CVEs rank first (KEV).
    assert {"CVE-2024-0001", "CVE-2024-0002"} <= set(rows)
    assert rows["CVE-2024-0001"]["kev"] is True
    assert rows["CVE-2024-0001"]["affected_resources"] == 1  # img:1.0, direct edge


def test_available_fixes_from_writer_edges(client: TestClient) -> None:
    rows = _get(client, "/v1/findings/available-fixes")
    # Only openssl carries a FixedVersion; spring ("") and the SBOM edges (no fix) drop out.
    assert [(r["component"], r["fix_version"]) for r in rows] == [("openssl", "1.1.1w")]
    assert rows[0]["cve_count"] == 1
    assert rows[0]["max_severity"] == "CRITICAL"


def test_sbom_reflects_recorded_packages(client: TestClient) -> None:
    rows = {r["name"]: r for r in _get(client, "/v1/inventory/sbom")}
    assert set(rows) == {"openssl", "zlib"}
    assert rows["openssl"]["image"] == "alpine:3.18"
    assert rows["openssl"]["vulnerabilities"] == 1  # package → VULNERABLE_TO → CVE


def test_container_images_rollup(client: TestClient) -> None:
    rows = {r["id"]: r for r in _get(client, "/v1/inventory/container-images")}
    # Only the SBOM image is kind=container-image; the scan-target resource is excluded.
    assert set(rows) == {"alpine:3.18"}
    assert rows["alpine:3.18"]["packages"] == 2  # CONTAINS_PACKAGE edges


def test_cloud_resources_include_both_writer_paths(client: TestClient) -> None:
    ids = {r["id"] for r in _get(client, "/v1/inventory/cloud-resources")}
    assert {"img:1.0", "alpine:3.18"} <= ids


def test_posture_is_non_empty(client: TestClient) -> None:
    data = _get(client, "/v1/posture")
    assert isinstance(data, dict)
    assert data["inventory_counts"]  # the rollup saw the writer's nodes
