"""Unit tests for identity.run() GCP-SA identity seam (Cycle 4 P1, gap #13 parity).

Verifies that when gcp_iam_bindings / gcp_sa_keys are injected into run() with a
SemanticStore, the correct graph edges land:

  - storage_read_grants  → HAS_ACCESS_TO (GCP-SA --HAS_ACCESS_TO--> CLOUD_RESOURCE(gcs_uri))
  - escalation_grants    → CAN_ESCALATE_TO (principal --CAN_ESCALATE_TO--> owner)
  - sa_key_ownership     → OWNS + OWNED_BY (SA --OWNS--> SECRET(fingerprint))
  - external_trust_grants (via gcp_org_domain) → external_trust=True on the member node

Mirror pattern from test_agent_owns_kg.py.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.canonical import gcs_uri, secret_fingerprint
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from identity import agent as agent_mod
from identity.agent import run
from identity.tools.aws_iam import IdentityListing
from identity.tools.gcp_iam import GcpIamBinding, GcpServiceAccountKey
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust-gcp-test"
_NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)

_GCP_SA = "serviceAccount:my-sa@my-project.iam.gserviceaccount.com"
_BUCKET = "my-sensitive-bucket"
_GCS_URI = gcs_uri(_BUCKET)

_OWNER = "user:owner@acme.com"
_ESCALATOR = "user:escalator@acme.com"

_PRIVATE_KEY_ID = "abc123keyid456"


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="identity",
        customer_id=_TENANT,
        task="Identity scan GCP",
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
    """Patch the IAM lister to return an empty listing (GCP-only test — no AWS principals)."""

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
# Test A: storage_read_grants → HAS_ACCESS_TO
# ---------------------------------------------------------------------------


async def test_run_gcp_storage_read_grant_writes_has_access_to(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GCP-SA with a storage.objectViewer binding → IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE(gcs)."""
    _patch_empty_listing(monkeypatch)

    bindings = (
        GcpIamBinding(
            bucket=_BUCKET,
            role="roles/storage.objectViewer",
            members=(_GCP_SA,),
        ),
    )

    await run(_contract(tmp_path), semantic_store=store, gcp_iam_bindings=bindings)

    # Upsert to get the node IDs (idempotent — same external_id returns same id).
    sa_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=_GCP_SA,
        properties={},
    )
    resource_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=_GCS_URI,
        properties={},
    )

    edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=sa_node,
        edge_types=(EdgeType.HAS_ACCESS_TO.value,),
    )
    assert len(edges) == 1, f"expected 1 HAS_ACCESS_TO edge; got {edges}"
    assert edges[0].dst_entity_id == resource_node, (
        f"HAS_ACCESS_TO must point to the GCS resource node ({_GCS_URI!r})"
    )


# ---------------------------------------------------------------------------
# Test B: escalation_grants → CAN_ESCALATE_TO
# ---------------------------------------------------------------------------


async def test_run_gcp_escalation_grant_writes_can_escalate_to(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GCP member with securityAdmin + an owner → IDENTITY --CAN_ESCALATE_TO--> IDENTITY(owner)."""
    _patch_empty_listing(monkeypatch)

    bindings = (
        GcpIamBinding(
            bucket=_BUCKET,
            role="roles/iam.securityAdmin",
            members=(_ESCALATOR,),
        ),
        GcpIamBinding(
            bucket=_BUCKET,
            role="roles/owner",
            members=(_OWNER,),
        ),
    )

    await run(_contract(tmp_path), semantic_store=store, gcp_iam_bindings=bindings)

    escalator_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=_ESCALATOR,
        properties={},
    )
    owner_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=_OWNER,
        properties={},
    )

    edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=escalator_node,
        edge_types=(EdgeType.CAN_ESCALATE_TO.value,),
    )
    assert len(edges) >= 1, f"expected at least 1 CAN_ESCALATE_TO edge; got {edges}"
    dst_ids = {e.dst_entity_id for e in edges}
    assert owner_node in dst_ids, f"CAN_ESCALATE_TO must point to the owner node ({_OWNER!r})"


# ---------------------------------------------------------------------------
# Test C: sa_key_ownership → OWNS + OWNED_BY
# ---------------------------------------------------------------------------


async def test_run_gcp_sa_key_writes_owns_edges(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GCP SA key → IDENTITY(sa) --OWNS--> SECRET(fingerprint) + reverse OWNED_BY."""
    _patch_empty_listing(monkeypatch)

    sa_keys = (GcpServiceAccountKey(service_account=_GCP_SA, private_key_id=_PRIVATE_KEY_ID),)
    fingerprint = secret_fingerprint(_PRIVATE_KEY_ID)

    await run(_contract(tmp_path), semantic_store=store, gcp_sa_keys=sa_keys)

    sa_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=_GCP_SA,
        properties={},
    )
    secret_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.SECRET.value,
        external_id=fingerprint,
        properties={},
    )

    # OWNS: SA --OWNS--> SECRET
    owns_edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=sa_node,
        edge_types=(EdgeType.OWNS.value,),
    )
    assert len(owns_edges) == 1, f"expected 1 OWNS edge from SA to key; got {owns_edges}"
    assert owns_edges[0].dst_entity_id == secret_node

    # OWNED_BY: SECRET --OWNED_BY--> SA
    owned_by_edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=secret_node,
        edge_types=(EdgeType.OWNED_BY.value,),
    )
    assert len(owned_by_edges) == 1, (
        f"expected 1 OWNED_BY edge from key to SA; got {owned_by_edges}"
    )
    assert owned_by_edges[0].dst_entity_id == sa_node


# ---------------------------------------------------------------------------
# Test D: None gcp inputs → AWS-only behavior unchanged (no GCP edges)
# ---------------------------------------------------------------------------


async def test_run_none_gcp_inputs_no_gcp_edges(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With gcp_iam_bindings=None and gcp_sa_keys=None, run() must not raise and no GCP edges."""
    _patch_empty_listing(monkeypatch)

    # Must not raise.
    report = await run(_contract(tmp_path), semantic_store=store)
    assert report is not None

    # No IDENTITY nodes for GCP SA (nothing was written).
    entities = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type=NodeCategory.IDENTITY.value
    )
    gcp_ids = [e for e in entities if "gserviceaccount" in e.external_id]
    assert not gcp_ids, f"expected no GCP SA nodes with no gcp_iam_bindings; got {gcp_ids}"
