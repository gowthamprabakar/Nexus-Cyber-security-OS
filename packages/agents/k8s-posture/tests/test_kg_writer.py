"""Tests for the k8s-posture knowledge-graph writer (v0.4 Stage 1.3/D.6).

Two surfaces:

1. **Direct** ``record_inventory`` against a real in-memory ``SemanticStore`` — proves
   the rich cluster graph: K8S_OBJECT nodes (namespaces / service accounts / RBAC roles),
   ``CONTAINS``, the **IRSA bridge** (service account → IAM-role IDENTITY node, the same
   node D.2 writes), and ``BINDS``.
2. **Wired** through ``agent.run()`` — opt-in + live-only: the inventory reader is patched
   (typed source, no OCSF reverse-parse); default (no store / no cluster) writes nothing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from k8s_posture import agent as agent_mod
from k8s_posture.agent import run
from k8s_posture.kg_writer import KnowledgeGraphWriter
from k8s_posture.rbac.enumerate import Role, RoleBinding, Subject
from k8s_posture.tools.cluster_inventory import ClusterInventory, K8sServiceAccount
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust_test"
_CLUSTER = "test-cluster"
_ROLE_ARN = "arn:aws:iam::111122223333:role/app-role"


def _inventory() -> ClusterInventory:
    return ClusterInventory(
        cluster_id=_CLUSTER,
        namespaces=("default",),
        service_accounts=(
            K8sServiceAccount(name="app-sa", namespace="default", role_arn=_ROLE_ARN),
            K8sServiceAccount(name="plain-sa", namespace="default"),
        ),
        roles=(Role(name="reader", kind="Role", namespace="default"),),
        role_bindings=(
            RoleBinding(
                name="rb",
                kind="RoleBinding",
                namespace="default",
                role_ref_kind="Role",
                role_ref_name="reader",
                subjects=(Subject(kind="ServiceAccount", name="app-sa", namespace="default"),),
            ),
        ),
    )


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_record_inventory_writes_objects_irsa_bridge_and_binds(store: SemanticStore) -> None:
    kg = KnowledgeGraphWriter(store, _TENANT)
    await kg.record_inventory(_inventory())

    objects = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="k8s_object")
    by_ext = {o.external_id: o for o in objects}
    ns_key = f"{_CLUSTER}/namespace/default"
    app_sa_key = f"{_CLUSTER}/namespace/default/serviceaccount/app-sa"
    role_key = f"{_CLUSTER}/role/default/reader"
    assert ns_key in by_ext
    assert app_sa_key in by_ext
    assert f"{_CLUSTER}/namespace/default/serviceaccount/plain-sa" in by_ext
    assert role_key in by_ext
    assert by_ext[app_sa_key].properties["kind"] == "service-account"

    # IRSA bridge: the IAM role is an IDENTITY node keyed by ARN (same node D.2 writes).
    identities = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="identity")
    assert [i.external_id for i in identities] == [_ROLE_ARN]

    # app-sa's outgoing edges: IRSA_MAPPING → role ARN, BINDS → reader role.
    app_sa = by_ext[app_sa_key]
    sa_neighbors = {
        n.external_id
        for n in await store.neighbors(tenant_id=_TENANT, entity_id=app_sa.entity_id, depth=1)
    }
    assert _ROLE_ARN in sa_neighbors  # IRSA bridge
    assert role_key in sa_neighbors  # BINDS

    # CONTAINS: namespace → app-sa.
    ns_neighbors = {
        n.external_id
        for n in await store.neighbors(
            tenant_id=_TENANT, entity_id=by_ext[ns_key].entity_id, depth=1
        )
    }
    assert app_sa_key in ns_neighbors


async def test_plain_sa_has_no_irsa_edge(store: SemanticStore) -> None:
    kg = KnowledgeGraphWriter(store, _TENANT)
    await kg.record_inventory(_inventory())
    # The only IDENTITY node is the single annotated SA's role — plain-sa contributes none.
    identities = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="identity")
    assert len(identities) == 1


# ----------------------------- wired through run() --------------------------


def _contract(tmp_path: Path, *, permitted: list[str]) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="k8s_posture",
        customer_id=_TENANT,
        task="Kubernetes posture scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=10, mb_written=10
        ),
        permitted_tools=permitted,
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


async def test_run_with_store_and_live_cluster_writes_graph(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_inventory(**_: Any) -> ClusterInventory:
        return _inventory()

    async def fake_workloads(**_: Any) -> tuple[()]:
        return ()

    monkeypatch.setattr(agent_mod, "read_cluster_inventory", fake_inventory)
    monkeypatch.setattr(agent_mod, "read_cluster_workloads", fake_workloads)

    kc = tmp_path / "kubeconfig"
    contract = _contract(tmp_path, permitted=["read_cluster_workloads", "read_cluster_inventory"])
    await run(contract, kubeconfig=kc, semantic_store=store)

    objects = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="k8s_object")
    assert any(o.external_id.endswith("/serviceaccount/app-sa") for o in objects)


async def test_run_without_cluster_writes_nothing(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_kb(*, path: Path, **_: Any) -> tuple[()]:
        return ()

    monkeypatch.setattr(agent_mod, "read_kube_bench", fake_kb)

    # semantic_store IS provided, but there's no live cluster source (feeds only) →
    # the inventory gate is skipped, nothing is written.
    contract = _contract(tmp_path, permitted=["read_kube_bench", "read_polaris", "read_manifests"])
    await run(contract, kube_bench_feed=tmp_path / "kb.json", semantic_store=store)
    assert await store.list_entities_by_type(tenant_id=_TENANT, entity_type="k8s_object") == []
