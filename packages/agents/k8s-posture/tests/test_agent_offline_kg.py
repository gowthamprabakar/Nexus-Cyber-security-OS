"""TDD test: feed-driven (offline) runs populate the knowledge graph.

Today (pre-fix) the guard at agent.py:190 requires a live cluster source, so an
offline manifest scan writes NOTHING to the graph even when semantic_store is
injected. This test drives run() with manifest_dir containing a privileged pod,
no kubeconfig/in_cluster, and asserts that BOTH:

  (a) the inventory node lands  — proves the guard was relaxed
  (b) the privileged K8S_OBJECT node lands  — proves record_privileged_workloads was called
  (c) image_ref equals the REAL container image, not the synthetic manifest-scan/... fallback

Step 2: run before the implementation → both assertions FAIL (guard blocks offline writes).
Step 4: run after the implementation → both PASS.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
import yaml
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from k8s_posture import agent as agent_mod
from k8s_posture.agent import run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust_offline_kg"
_CLUSTER_ID = "offline-test-cluster"
_REAL_IMAGE = "ghcr.io/attack/tool:latest"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="k8s_posture",
        customer_id=_TENANT,
        task="Kubernetes posture scan (offline)",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=10, mb_written=10
        ),
        permitted_tools=["read_kube_bench", "read_polaris", "read_manifests"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _privileged_pod_manifest(*, name: str, namespace: str, image: str) -> dict[str, Any]:
    """A Pod manifest with a single privileged container."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "containers": [
                {
                    "name": "pwned",
                    "image": image,
                    "securityContext": {"privileged": True},
                }
            ]
        },
    }


# ---------------------------------------------------------------------------
# Test: offline manifest scan writes graph nodes
# ---------------------------------------------------------------------------


async def test_offline_manifest_writes_inventory_and_privileged_node(
    tmp_path: Path, store: SemanticStore
) -> None:
    """
    Drive run() with manifest_dir (offline) containing a privileged pod.
    No kubeconfig, no in_cluster. Uses the REAL read_manifests reader — no monkeypatching.

    Asserts:
      (a) at least one K8S_OBJECT node lands in the store (guard relaxed — offline
          feed-driven writes now happen).
      (b) a K8S_OBJECT node with privileged=True lands (record_privileged_workloads
          was called and wrote the pod node).
      (c) the privileged workload's image_ref is the REAL container image from the manifest
          (not the synthetic "manifest-scan/..." fallback — proves unmapped["image"] is set
          by the real reader's _check_container_rules for privileged-container findings).
    """
    # Build a manifest directory with one privileged pod.
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()
    pod_manifest = _privileged_pod_manifest(
        name="pwned-pod", namespace="kube-system", image=_REAL_IMAGE
    )
    (manifest_dir / "pwned-pod.yaml").write_text(yaml.safe_dump(pod_manifest))

    # No monkeypatching — the real read_manifests reader parses the YAML on disk.
    contract = _contract(tmp_path)
    await run(
        contract,
        manifest_dir=manifest_dir,
        semantic_store=store,
        # no kubeconfig, no in_cluster
    )

    # (a) At least one K8S_OBJECT node must exist (guard was relaxed for offline feeds).
    objects = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="k8s_object")
    assert objects, "expected K8S_OBJECT nodes from offline manifest scan, got none"

    # (b) A pod node with privileged=True must exist (record_privileged_workloads was called).
    privileged_pods = [o for o in objects if o.properties.get("privileged") is True]
    assert privileged_pods, (
        "expected a privileged K8S_OBJECT node (privileged=True) from record_privileged_workloads, "
        "got none — offline guard was not relaxed or privileged-workload derive is missing"
    )
    assert privileged_pods[0].properties.get("name") == "pwned-pod"

    # (c) The RUNS_IMAGE edge must point to the REAL image from the manifest.
    # record_privileged_workloads writes a CLOUD_RESOURCE node keyed by image_ref.
    # If the reader set unmapped["image"] correctly, that node's external_id = _REAL_IMAGE.
    # If it fell back to the synthetic key, external_id = "manifest-scan/..." instead.
    image_nodes = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource")
    container_image_nodes = [
        n for n in image_nodes if n.properties.get("kind") == "container-image"
    ]
    assert container_image_nodes, (
        "expected a container-image CLOUD_RESOURCE node from RUNS_IMAGE edge"
    )
    image_ids = [n.external_id for n in container_image_nodes]
    assert _REAL_IMAGE in image_ids, (
        f"expected container-image node with external_id={_REAL_IMAGE!r}, got {image_ids!r} — "
        "real reader is not setting unmapped['image'] on privileged-container findings "
        "(RUNS_IMAGE edge falls back to synthetic manifest-scan/... key)"
    )


async def test_offline_cluster_reader_writes_rbac_nodes(
    tmp_path: Path, store: SemanticStore
) -> None:
    """ClusterReader seam: offline run() with cluster_reader writes SA + role nodes.

    No kubeconfig, no in_cluster, no manifest_dir.  The injectable ClusterReader is the
    only source.  Asserts that record_inventory fired (K8S_OBJECT nodes landed) and that
    the SA node is present for the expected namespace/name.
    """
    from fleet_testkit.k8s_workloads import cluster_admin_rbac_reader

    reader = cluster_admin_rbac_reader(namespace="test-ns", sa_name="admin-sa", admin=True)
    contract = _contract(tmp_path)
    await run(
        contract,
        cluster_reader=reader,
        semantic_store=store,
        # no manifest_dir, no kubeconfig, no in_cluster
    )

    objects = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="k8s_object")
    assert objects, "expected K8S_OBJECT nodes written via cluster_reader seam, got none"

    sa_nodes = [o for o in objects if o.properties.get("kind") == "service-account"]
    assert sa_nodes, "expected a service-account K8S_OBJECT node from record_inventory"
    assert any(
        o.properties.get("name") == "admin-sa" and o.properties.get("namespace") == "test-ns"
        for o in sa_nodes
    ), f"expected SA admin-sa in test-ns; got {[o.properties for o in sa_nodes]}"


async def test_offline_cluster_reader_none_skips_cleanly(
    tmp_path: Path, store: SemanticStore
) -> None:
    """cluster_reader=None (default) → no K8S_OBJECT nodes written (existing tests stay green)."""
    await run(
        _contract(tmp_path),
        semantic_store=store,
        # no cluster_reader, no manifest_dir, no feeds
    )
    objects = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="k8s_object")
    assert objects == [], (
        "expected no K8S_OBJECT nodes when cluster_reader is None and no feeds are provided"
    )


async def test_offline_kube_bench_only_writes_nothing_to_graph(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """kube-bench feed with NO privileged-container findings → no graph nodes written.

    This ensures the guard relaxation doesn't produce spurious nodes when there are
    no manifest findings (kube-bench + polaris findings carry no pod-graph data).
    """
    from k8s_posture.tools.kube_bench import KubeBenchFinding

    kb_feed = tmp_path / "kb.json"
    kb_feed.write_text("{}")

    async def fake_kb(*, path: Path, **_: Any) -> tuple[KubeBenchFinding, ...]:
        return ()

    monkeypatch.setattr(agent_mod, "read_kube_bench", fake_kb)

    await run(
        _contract(tmp_path),
        kube_bench_feed=kb_feed,
        semantic_store=store,
    )

    objects = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="k8s_object")
    assert objects == [], (
        "expected no K8S_OBJECT nodes when kube-bench feed has no privileged-container findings"
    )
