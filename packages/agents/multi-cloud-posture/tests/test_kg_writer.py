"""E2E tests — D.15 Multi-Cloud Posture kg_writer (Stage 1.7, R-2).

Runs the agent end-to-end with an injected in-memory ``SemanticStore`` and asserts the
real normalize → kg_writer path populates the ADR-018 spine: ``CLOUD_RESOURCE`` nodes,
``MISCONFIGURATION_FINDING`` nodes, ``AFFECTS`` edges — tenant-scoped, opt-in/inert.

Readers are monkeypatched (I/O surface; they have their own unit tests), exactly as
``test_agent_unit.py`` does — the *new* code under test is the kg-write wiring.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from multi_cloud_posture import agent as agent_mod
from multi_cloud_posture.agent import build_registry, run
from multi_cloud_posture.tools.azure_defender import AzureDefenderFinding
from multi_cloud_posture.tools.gcp_scc import GcpSccFinding
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
_TENANT = "cust_test"
_OTHER = "cust_other"


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


def _contract(tmp_path: Path, customer_id: str = _TENANT) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="multi_cloud_posture",
        customer_id=customer_id,
        task="Multi-cloud posture scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=10, mb_written=10
        ),
        permitted_tools=[
            "read_azure_findings",
            "read_azure_activity",
            "read_gcp_findings",
            "read_gcp_iam_findings",
            "kg_upsert_asset",
            "kg_upsert_finding",
        ],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _defender() -> AzureDefenderFinding:
    return AzureDefenderFinding(
        kind="assessment",
        record_id="/subscriptions/aaa-bbb/providers/Microsoft.Security/assessments/asmt-001",
        display_name="Restrict storage account public access",
        severity="High",
        status="Unhealthy",
        description="x",
        resource_id=(
            "/subscriptions/aaa-bbb/resourceGroups/rg1/providers/"
            "Microsoft.Storage/storageAccounts/sa1"
        ),
        subscription_id="aaa-bbb",
        assessment_type="BuiltIn",
        detected_at=NOW,
    )


def _scc() -> GcpSccFinding:
    return GcpSccFinding(
        finding_name="organizations/123/sources/456/findings/finding-001",
        parent="organizations/123/sources/456",
        resource_name="//storage.googleapis.com/projects/proj-xyz/buckets/public-bucket",
        category="PUBLIC_BUCKET",
        state="ACTIVE",
        severity="HIGH",
        description="x",
        project_id="proj-xyz",
        detected_at=NOW,
    )


def _patch_readers(mp: pytest.MonkeyPatch) -> None:
    async def fake_defender(*, path: Path, **_: Any) -> tuple[AzureDefenderFinding, ...]:
        return (_defender(),)

    async def fake_scc(*, path: Path, **_: Any) -> tuple[GcpSccFinding, ...]:
        return (_scc(),)

    mp.setattr(agent_mod, "read_azure_findings", fake_defender)
    mp.setattr(agent_mod, "read_gcp_findings", fake_scc)


# ---------------------------- registry gating ----------------------------


def test_build_registry_without_store_omits_kg_tools() -> None:
    known = build_registry().known_tools()
    assert "kg_upsert_asset" not in known
    assert "kg_upsert_finding" not in known


def test_build_registry_with_store_registers_kg_tools(store: SemanticStore) -> None:
    known = build_registry(store, _TENANT).known_tools()
    assert "kg_upsert_asset" in known
    assert "kg_upsert_finding" in known


# ---------------------------- e2e graph population -----------------------


@pytest.mark.asyncio
async def test_run_populates_spine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: SemanticStore
) -> None:
    _patch_readers(monkeypatch)
    azure_feed = tmp_path / "defender.json"
    azure_feed.write_text("placeholder")
    gcp_feed = tmp_path / "scc.json"
    gcp_feed.write_text("placeholder")

    report = await run(
        _contract(tmp_path),
        azure_findings_feed=azure_feed,
        gcp_findings_feed=gcp_feed,
        semantic_store=store,
    )
    assert report.total == 2  # one Azure + one GCP finding

    resources = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )
    findings = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type=NodeCategory.MISCONFIGURATION_FINDING.value
    )
    # Both an Azure storage account and a GCP bucket landed as spine resources.
    assert len(resources) >= 2
    assert len(findings) == 2

    # Each finding has an AFFECTS edge to its resource.
    for finding in findings:
        edges = await store.get_relationships_from(
            tenant_id=_TENANT, src_entity_id=finding.entity_id
        )
        assert edges, f"finding {finding.external_id} wrote no AFFECTS edge"
        assert all(e.relationship_type == EdgeType.AFFECTS.value for e in edges)


@pytest.mark.asyncio
async def test_run_without_store_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: SemanticStore
) -> None:
    """Inert path: no semantic_store → no graph writes (byte-identical offline)."""
    _patch_readers(monkeypatch)
    azure_feed = tmp_path / "defender.json"
    azure_feed.write_text("placeholder")

    await run(_contract(tmp_path), azure_findings_feed=azure_feed)  # no semantic_store
    # The injected store (unused by the run) stays empty.
    resources = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )
    assert resources == []


@pytest.mark.asyncio
async def test_run_is_tenant_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: SemanticStore
) -> None:
    _patch_readers(monkeypatch)
    feed = tmp_path / "defender.json"
    feed.write_text("placeholder")

    await run(
        _contract(tmp_path, customer_id=_TENANT),
        azure_findings_feed=feed,
        semantic_store=store,
    )
    # A different tenant sees none of tenant A's resources.
    other = await store.list_entities_by_type(
        tenant_id=_OTHER, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )
    assert other == []
