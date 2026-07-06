"""Unit tests for identity.run() Azure-MI identity seam (Cycle 4 P1b, gap #13 parity).

Verifies that when azure_role_assignments / azure_ad_listing are injected into run()
with a SemanticStore, the correct graph edges land:

  - blob_read_grants       → HAS_ACCESS_TO (Azure-MI --HAS_ACCESS_TO--> CLOUD_RESOURCE(azure_blob_uri))
  - escalation_grants      → CAN_ESCALATE_TO (principal --CAN_ESCALATE_TO--> owner)
  - sp_credential_ownership → OWNS + OWNED_BY (SP --OWNS--> SECRET(fingerprint))
  - external_trust_grants (via guest_principal_ids from azure_ad_listing) → external_trust=True

Mirror pattern from test_gcp_identity_seam.py.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.canonical import azure_blob_uri, secret_fingerprint
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from identity import agent as agent_mod
from identity.agent import run
from identity.tools.aws_iam import IdentityListing
from identity.tools.azure_ad import (
    AzureAdListing,
    AzureAdServicePrincipal,
    azure_sp_key,
)
from identity.tools.azure_rbac import AzureRoleAssignment
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust-azure-test"
_NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)

_AZURE_MI_ID = "mi-obj-id-abc123"  # managed identity principal_id (object ID)
_STORAGE_ACCOUNT = "mystorage"
_CONTAINER = "pii-container"
_AZURE_BLOB = azure_blob_uri(_STORAGE_ACCOUNT, _CONTAINER)

_OWNER_ID = "owner-obj-id-xyz"
_ESCALATOR_ID = "escalator-obj-id-def"

_SP_APP_ID = "app-id-sp-secret-999"
_SP_ID = "sp-obj-id-sp-secret-999"


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="identity",
        customer_id=_TENANT,
        task="Identity scan Azure",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=500, mb_written=10
        ),
        permitted_tools=["aws_iam_list_identities"],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _patch_empty_listing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the IAM lister to return an empty listing (Azure-only test — no AWS principals)."""

    async def fake_list(**_: Any) -> IdentityListing:
        return IdentityListing(users=(), roles=(), groups=())

    monkeypatch.setattr(agent_mod, "aws_iam_list_identities", fake_list)


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Test A: blob_read_grants → HAS_ACCESS_TO
# ---------------------------------------------------------------------------


async def test_run_azure_blob_read_grant_writes_has_access_to(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Azure-MI with Storage Blob Data Reader on a container → IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE(azure_blob_uri)."""
    _patch_empty_listing(monkeypatch)

    assignments = (
        AzureRoleAssignment(
            principal_id=_AZURE_MI_ID,
            role_name="Storage Blob Data Reader",
            scope=f"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/{_STORAGE_ACCOUNT}/blobServices/default/containers/{_CONTAINER}",
        ),
    )

    await run(_contract(tmp_path), semantic_store=store, azure_role_assignments=assignments)

    mi_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=_AZURE_MI_ID,
        properties={},
    )
    resource_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=_AZURE_BLOB,
        properties={},
    )

    edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=mi_node,
        edge_types=(EdgeType.HAS_ACCESS_TO.value,),
    )
    assert len(edges) == 1, f"expected 1 HAS_ACCESS_TO edge; got {edges}"
    assert edges[0].dst_entity_id == resource_node, (
        f"HAS_ACCESS_TO must point to the Azure Blob resource node ({_AZURE_BLOB!r})"
    )


# ---------------------------------------------------------------------------
# Test B: escalation_grants → CAN_ESCALATE_TO
# ---------------------------------------------------------------------------


async def test_run_azure_escalation_grant_writes_can_escalate_to(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Azure principal with User Access Administrator + an Owner → IDENTITY --CAN_ESCALATE_TO--> IDENTITY(owner)."""
    _patch_empty_listing(monkeypatch)

    assignments = (
        AzureRoleAssignment(
            principal_id=_ESCALATOR_ID,
            role_name="User Access Administrator",
            scope="/subscriptions/sub-1",
        ),
        AzureRoleAssignment(
            principal_id=_OWNER_ID,
            role_name="Owner",
            scope="/subscriptions/sub-1",
        ),
    )

    await run(_contract(tmp_path), semantic_store=store, azure_role_assignments=assignments)

    escalator_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=_ESCALATOR_ID,
        properties={},
    )
    owner_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=_OWNER_ID,
        properties={},
    )

    edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=escalator_node,
        edge_types=(EdgeType.CAN_ESCALATE_TO.value,),
    )
    assert len(edges) >= 1, f"expected at least 1 CAN_ESCALATE_TO edge; got {edges}"
    dst_ids = {e.dst_entity_id for e in edges}
    assert owner_node in dst_ids, f"CAN_ESCALATE_TO must point to the owner node ({_OWNER_ID!r})"


# ---------------------------------------------------------------------------
# Test C: sp_credential_ownership → OWNS + OWNED_BY (keyed on FINGERPRINT, no plaintext)
# ---------------------------------------------------------------------------


async def test_run_azure_sp_credential_writes_owns_edges(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Azure SP → IDENTITY(sp) --OWNS--> SECRET(fingerprint) + reverse OWNED_BY; fingerprint not plaintext."""
    _patch_empty_listing(monkeypatch)

    sp = AzureAdServicePrincipal(
        id=_SP_ID,
        app_id=_SP_APP_ID,
        display_name="test-sp",
        sp_type="Application",
        account_enabled=True,
    )
    ad_listing = AzureAdListing(
        users=(),
        groups=(),
        service_principals=(sp,),
    )
    fingerprint = secret_fingerprint(_SP_APP_ID)

    await run(_contract(tmp_path), semantic_store=store, azure_ad_listing=ad_listing)

    sp_key = azure_sp_key(_SP_APP_ID)
    sp_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=sp_key,
        properties={},
    )
    secret_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.SECRET.value,
        external_id=fingerprint,
        properties={},
    )

    # Fingerprint must not be the raw app_id (no plaintext).
    assert fingerprint != _SP_APP_ID, "fingerprint must be hashed, not raw app_id"

    # OWNS: SP --OWNS--> SECRET
    owns_edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=sp_node,
        edge_types=(EdgeType.OWNS.value,),
    )
    assert len(owns_edges) == 1, f"expected 1 OWNS edge from SP to secret; got {owns_edges}"
    assert owns_edges[0].dst_entity_id == secret_node

    # OWNED_BY: SECRET --OWNED_BY--> SP
    owned_by_edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=secret_node,
        edge_types=(EdgeType.OWNED_BY.value,),
    )
    assert len(owned_by_edges) == 1, (
        f"expected 1 OWNED_BY edge from secret to SP; got {owned_by_edges}"
    )
    assert owned_by_edges[0].dst_entity_id == sp_node


# ---------------------------------------------------------------------------
# Test D: None azure inputs → unchanged behavior (no Azure edges)
# ---------------------------------------------------------------------------


async def test_run_none_azure_inputs_no_azure_edges(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With azure_role_assignments=None and azure_ad_listing=None, run() must not raise and no Azure edges."""
    _patch_empty_listing(monkeypatch)

    # Must not raise.
    report = await run(_contract(tmp_path), semantic_store=store)
    assert report is not None

    # No IDENTITY nodes for Azure MI (nothing was written).
    entities = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type=NodeCategory.IDENTITY.value
    )
    azure_ids = [e for e in entities if "blob.core.windows.net" in e.external_id]
    assert not azure_ids, f"expected no Azure blob nodes with no azure inputs; got {azure_ids}"
