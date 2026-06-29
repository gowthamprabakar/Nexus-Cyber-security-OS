"""Cross-cloud path 6 (gap #13) — privileged pod + vulnerable image on AKS AND GKE, REAL e2e.

The kind e2e proves the live-kubectl wiring; this proves the SAME real privileged-pod parser +
``record_privileged_workloads`` handle managed-cluster (AKS / GKE) ``kubectl get pods -o json``
payloads — provider-specific node names / labels / registry image refs and all — so
``find_privileged_vulnerable_workload`` (path 6) fires cross-cloud. The vuln leg is REAL trivy
(trivy-gated, same grade as the kind e2e); the k8s leg is hermetic (parser takes a JSON dict).
"""

import pytest
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.k8s_workloads import drive_privileged_workloads, managed_cluster_pods
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

pytestmark = pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")

_TENANT = "tenant-xcloud-k8s"
_AKS_IMAGE = "acme.azurecr.io/app:1.0"
_GKE_IMAGE = "gcr.io/acme-prod/app:1.0"


def _write_vulnerable_fixture(root) -> None:
    (root / "requirements.txt").write_text("Django==2.0.0\n")


@pytest.mark.asyncio
async def test_aks_privileged_pod_with_vulnerable_image_lights_up(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    pods = managed_cluster_pods(
        name="web",
        image=_AKS_IMAGE,
        privileged=True,
        node_name="aks-nodepool1-12345-vmss000000",
        node_labels={"kubernetes.azure.com/cluster": "mc-rg-aks"},
    )
    async with in_memory_semantic_store() as store:
        await drive_privileged_workloads(
            store, tenant_id=_TENANT, cluster_id="aks-prod", pods_json=pods
        )
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_AKS_IMAGE
        )
        hits = await KgQuery(store, _TENANT).find_privileged_vulnerable_workload()
        assert hits, "privileged AKS pod running a vulnerable image surfaces a path-6 hit"
        assert all(h.cve_id for h in hits)


@pytest.mark.asyncio
async def test_gke_privileged_pod_with_vulnerable_image_lights_up(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    pods = managed_cluster_pods(
        name="web",
        image=_GKE_IMAGE,
        privileged=True,
        node_name="gke-acme-default-pool-abc123-x1y2",
        node_labels={"cloud.google.com/gke-nodepool": "default-pool"},
    )
    async with in_memory_semantic_store() as store:
        await drive_privileged_workloads(
            store, tenant_id=_TENANT, cluster_id="gke-prod", pods_json=pods
        )
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_GKE_IMAGE
        )
        hits = await KgQuery(store, _TENANT).find_privileged_vulnerable_workload()
        assert hits, "privileged GKE pod running a vulnerable image surfaces a path-6 hit"
        assert all(h.cve_id for h in hits)


@pytest.mark.asyncio
async def test_non_privileged_managed_pod_is_dark(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    pods = managed_cluster_pods(
        name="web",
        image=_AKS_IMAGE,
        privileged=False,  # same vulnerable image, but NOT privileged → no node-escape path
        node_name="aks-nodepool1-12345-vmss000000",
        node_labels={"kubernetes.azure.com/cluster": "mc-rg-aks"},
    )
    async with in_memory_semantic_store() as store:
        recorded = await drive_privileged_workloads(
            store, tenant_id=_TENANT, cluster_id="aks-prod", pods_json=pods
        )
        assert recorded == 0  # the parser only records privileged pods
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_AKS_IMAGE
        )
        assert await KgQuery(store, _TENANT).find_privileged_vulnerable_workload() == []
