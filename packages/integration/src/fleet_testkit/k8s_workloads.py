"""In-memory K8s privileged-workload harness — cross-cloud path-6 proof (gap #13).

The k8s layer is already cloud-agnostic: ``read_privileged_workloads`` parses
``kubectl get pods -o json``, whose pod spec is identical on kind / AKS / GKE — only provider
metadata (node names, labels, registry of the image ref) differs, and the parser ignores it. The
live ``kind`` e2e proves the kubectl wiring; this harness proves the SAME real parser +
``record_privileged_workloads`` handle managed-cluster (AKS / GKE) payloads, so
``find_privileged_vulnerable_workload`` (path 6) fires on any cluster with no change.

``managed_cluster_pods`` builds a realistic single-pod payload carrying provider-specific fields
(node name, cloud node labels) the parser must look past; ``drive_privileged_workloads`` runs the
REAL parser + writer into a store.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from k8s_posture.kg_writer import KnowledgeGraphWriter as K8sKgWriter
from k8s_posture.tools.privileged_pods import privileged_workloads

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore


def managed_cluster_pods(
    *,
    name: str,
    image: str,
    privileged: bool,
    node_name: str,
    node_labels: dict[str, str],
    namespace: str = "default",
) -> dict[str, Any]:
    """A realistic ``kubectl get pods -o json`` doc for one pod on a managed (AKS/GKE) cluster.

    Carries provider-specific metadata (``spec.nodeName``, cloud node labels) the cloud-agnostic
    parser ignores — present so the test proves the parser looks past managed-cluster shape.
    """
    container: dict[str, Any] = {"name": name, "image": image}
    if privileged:
        container["securityContext"] = {"privileged": True}
    return {
        "items": [
            {
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": node_labels,
                },
                "spec": {"nodeName": node_name, "containers": [container]},
            }
        ]
    }


async def drive_privileged_workloads(
    store: SemanticStore, *, tenant_id: str, cluster_id: str, pods_json: dict[str, Any]
) -> int:
    """Run k8s-posture's REAL privileged-pod parser + writer. Returns the count recorded."""
    workloads = privileged_workloads(pods_json)
    await K8sKgWriter(store, tenant_id).record_privileged_workloads(cluster_id, workloads)
    return len(workloads)


__all__ = ["drive_privileged_workloads", "managed_cluster_pods"]
