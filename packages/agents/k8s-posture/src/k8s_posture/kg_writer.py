"""K8s-posture knowledge-graph writer (v0.4 Stage 1.3/D.6).

Consumes the typed :class:`~k8s_posture.tools.cluster_inventory.ClusterInventory` and
writes the cluster identity + RBAC inventory into the fleet graph:

- Namespaces + service accounts + RBAC roles → ``K8S_OBJECT`` nodes (``kind`` property).
- ``CONTAINS``: namespace → service account.
- ``IRSA_MAPPING``: service account → the **IAM role** it assumes (an ``IDENTITY`` node
  keyed by role ARN — the *same* node D.2-identity writes). This is the headline bridge:
  it joins a K8s workload identity to its cloud identity, so a cluster-side finding and
  an IAM-side finding resolve to one connected subgraph in Stage 3 correlation.
- ``BINDS``: service-account subject → the RBAC role a RoleBinding grants it.

Subclasses :class:`KnowledgeGraphWriterBase` (ADR-019): tenant scoping, typed
vocabulary (ADR-018), within-run dedup, opt-in/inert when no store. Offline default
writes nothing → findings.json byte-identical. Reads the typed inventory, never OCSF
findings (no findings-derived reverse-parse).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

if TYPE_CHECKING:
    from k8s_posture.tools.cluster_inventory import ClusterInventory


def _ns_key(cluster: str, namespace: str) -> str:
    return f"{cluster}/namespace/{namespace}"


def _sa_key(cluster: str, namespace: str, name: str) -> str:
    return f"{cluster}/namespace/{namespace}/serviceaccount/{name}"


def _role_key(cluster: str, kind: str, namespace: str, name: str) -> str:
    return f"{cluster}/{kind.lower()}/{namespace}/{name}"


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Persists cluster namespaces / service-accounts / RBAC + the IRSA bridge."""

    async def record_inventory(self, inventory: ClusterInventory) -> None:
        """Upsert K8S_OBJECT nodes + CONTAINS / IRSA_MAPPING / BINDS edges (deduped)."""
        cluster = inventory.cluster_id

        ns_nodes: dict[str, str | None] = {}
        for ns in inventory.namespaces:
            ns_nodes[ns] = await self.upsert_node(
                NodeCategory.K8S_OBJECT,
                _ns_key(cluster, ns),
                {"kind": "namespace", "name": ns, "cluster_id": cluster},
            )

        sa_nodes: dict[tuple[str, str], str | None] = {}
        for sa in inventory.service_accounts:
            sa_node = await self.upsert_node(
                NodeCategory.K8S_OBJECT,
                _sa_key(cluster, sa.namespace, sa.name),
                {
                    "kind": "service-account",
                    "name": sa.name,
                    "namespace": sa.namespace,
                    "cluster_id": cluster,
                },
            )
            sa_nodes[(sa.namespace, sa.name)] = sa_node

            parent = ns_nodes.get(sa.namespace)
            if parent is None and sa.namespace:
                parent = await self.upsert_node(
                    NodeCategory.K8S_OBJECT,
                    _ns_key(cluster, sa.namespace),
                    {"kind": "namespace", "name": sa.namespace, "cluster_id": cluster},
                )
                ns_nodes[sa.namespace] = parent
            await self.add_edge(parent or "", sa_node or "", EdgeType.CONTAINS)

            # IRSA bridge: ServiceAccount -> assumed IAM role (IDENTITY by ARN).
            if sa.role_arn:
                role_node = await self.upsert_node(
                    NodeCategory.IDENTITY,
                    sa.role_arn,
                    {"name": sa.role_arn.rsplit("/", 1)[-1], "principal_type": "role"},
                )
                await self.add_edge(sa_node or "", role_node or "", EdgeType.IRSA_MAPPING)

        role_nodes: dict[tuple[str, str, str], str | None] = {}
        for role in inventory.roles:
            role_nodes[(role.kind, role.namespace, role.name)] = await self.upsert_node(
                NodeCategory.K8S_OBJECT,
                _role_key(cluster, role.kind, role.namespace, role.name),
                {
                    "kind": role.kind.lower(),
                    "name": role.name,
                    "namespace": role.namespace,
                    "cluster_id": cluster,
                },
            )

        for binding in inventory.role_bindings:
            role_ns = "" if binding.role_ref_kind == "ClusterRole" else binding.namespace
            role_node = role_nodes.get((binding.role_ref_kind, role_ns, binding.role_ref_name))
            if role_node is None:
                continue
            for subject in binding.subjects:
                if subject.kind != "ServiceAccount":
                    continue
                subj_node = sa_nodes.get((subject.namespace, subject.name))
                if subj_node is None:
                    subj_node = await self.upsert_node(
                        NodeCategory.K8S_OBJECT,
                        _sa_key(cluster, subject.namespace, subject.name),
                        {
                            "kind": "service-account",
                            "name": subject.name,
                            "namespace": subject.namespace,
                            "cluster_id": cluster,
                        },
                    )
                    sa_nodes[(subject.namespace, subject.name)] = subj_node
                await self.add_edge(subj_node or "", role_node or "", EdgeType.BINDS)


__all__ = ["KnowledgeGraphWriter"]
