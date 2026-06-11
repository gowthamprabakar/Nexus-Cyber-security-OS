"""Cloud-agnostic cluster auth resolution via kubeconfig (D.6 v0.2 Task 16).

Per **Q2** the kubeconfig **is** the interface — EKS, AKS, GKE, and self-managed clusters
are all reached the same way. This resolves a kubeconfig context to a typed
`ResolvedCluster` (cluster id + detected provider + server), so the live scanners can
target any provider without provider-specific code paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ClusterProvider(StrEnum):
    EKS = "eks"
    AKS = "aks"
    GKE = "gke"
    SELF_MANAGED = "self_managed"


class ClusterAuthError(RuntimeError):
    """The requested context / cluster could not be resolved from the kubeconfig."""


@dataclass(frozen=True, slots=True)
class ResolvedCluster:
    cluster_id: str
    provider: ClusterProvider
    server: str
    context: str


def detect_provider(*, cluster_name: str, server: str) -> ClusterProvider:
    """Heuristically detect the managed-K8s provider from the cluster name + server URL."""
    name = cluster_name.lower()
    host = server.lower()
    if name.startswith("gke_") or "container.googleapis.com" in host:
        return ClusterProvider.GKE
    if "eks.amazonaws.com" in host or name.startswith("arn:aws:eks"):
        return ClusterProvider.EKS
    if "azmk8s.io" in host:
        return ClusterProvider.AKS
    return ClusterProvider.SELF_MANAGED


def _named_entry(items: Any, name: str, key: str) -> dict[str, Any]:
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("name") == name:
                inner = item.get(key)
                return inner if isinstance(inner, dict) else {}
    return {}


def resolve_cluster(kubeconfig: dict[str, Any], *, context: str | None = None) -> ResolvedCluster:
    """Resolve a kubeconfig context → `ResolvedCluster`. Uses ``current-context`` when no
    context is given; raises if the context or its cluster is missing."""
    ctx_name = context or str(kubeconfig.get("current-context", ""))
    if not ctx_name:
        raise ClusterAuthError("no context given and kubeconfig has no current-context")

    ctx = _named_entry(kubeconfig.get("contexts"), ctx_name, "context")
    if not ctx:
        raise ClusterAuthError(f"context {ctx_name!r} not found in kubeconfig")

    cluster_name = str(ctx.get("cluster", ""))
    cluster = _named_entry(kubeconfig.get("clusters"), cluster_name, "cluster")
    if not cluster:
        raise ClusterAuthError(f"cluster {cluster_name!r} not found in kubeconfig")

    server = str(cluster.get("server", ""))
    return ResolvedCluster(
        cluster_id=cluster_name,
        provider=detect_provider(cluster_name=cluster_name, server=server),
        server=server,
        context=ctx_name,
    )
