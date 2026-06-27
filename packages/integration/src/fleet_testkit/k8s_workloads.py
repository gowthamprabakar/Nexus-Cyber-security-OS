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
from k8s_posture.tools.cluster_inventory import inventory_from_reader
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


class _CannedClusterReader:
    """A fake ``ClusterReader`` returning serialized RBAC dicts — the kube analogue of moto.

    Feeds the REAL :func:`inventory_from_reader` parser the exact dict shape the live kubernetes
    client serializes (``kind`` reinstated on list items), so the over-privileged-role parse runs
    for real against a stand-in cluster.
    """

    def __init__(
        self, *, sa_name: str, namespace: str, role_name: str, role_rules: list[dict[str, Any]]
    ) -> None:
        self._sa_name = sa_name
        self._namespace = namespace
        self._role_name = role_name
        self._role_rules = role_rules

    def list_namespaces(self) -> list[dict[str, Any]]:
        return [{"metadata": {"name": self._namespace}}]

    def list_service_accounts(self) -> list[dict[str, Any]]:
        return [{"metadata": {"name": self._sa_name, "namespace": self._namespace}}]

    def list_roles(self) -> list[dict[str, Any]]:
        return [
            {
                "kind": "ClusterRole",
                "metadata": {"name": self._role_name},
                "rules": self._role_rules,
            }
        ]

    def list_role_bindings(self) -> list[dict[str, Any]]:
        return [
            {
                "kind": "ClusterRoleBinding",
                "metadata": {"name": f"{self._role_name}-binding"},
                "roleRef": {"kind": "ClusterRole", "name": self._role_name},
                "subjects": [
                    {"kind": "ServiceAccount", "name": self._sa_name, "namespace": self._namespace}
                ],
            }
        ]


def cluster_admin_rbac_reader(
    *, sa_name: str = "deployer", namespace: str = "default", admin: bool = True
) -> _CannedClusterReader:
    """A canned reader: a ServiceAccount bound to a ClusterRole that is cluster-admin (``admin``)
    or scoped read-only (``not admin``). Drives path #20's over-privileged-role parse + writer."""
    rules = (
        [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        if admin
        else [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
    )
    return _CannedClusterReader(
        sa_name=sa_name, namespace=namespace, role_name="cluster-admin", role_rules=rules
    )


async def drive_cluster_inventory(
    store: SemanticStore, *, tenant_id: str, cluster_id: str, reader: _CannedClusterReader
) -> None:
    """Run k8s-posture's REAL RBAC inventory parser + writer (namespaces/SAs/roles/bindings)."""
    inventory = inventory_from_reader(reader, cluster_id=cluster_id)
    await K8sKgWriter(store, tenant_id).record_inventory(inventory)


__all__ = [
    "cluster_admin_rbac_reader",
    "drive_cluster_inventory",
    "drive_privileged_workloads",
    "managed_cluster_pods",
]
