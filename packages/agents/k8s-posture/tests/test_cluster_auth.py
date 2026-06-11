"""D.6 v0.2 Task 16 — cloud-agnostic cluster auth resolution tests (Q2)."""

from __future__ import annotations

from typing import Any

import pytest
from k8s_posture.cluster_auth import (
    ClusterAuthError,
    ClusterProvider,
    detect_provider,
    resolve_cluster,
)


def _kubeconfig(cluster_name: str, server: str, *, current: str = "ctx1") -> dict[str, Any]:
    return {
        "current-context": current,
        "contexts": [{"name": "ctx1", "context": {"cluster": cluster_name, "user": "u"}}],
        "clusters": [{"name": cluster_name, "cluster": {"server": server}}],
    }


def test_detect_eks() -> None:
    assert (
        detect_provider(cluster_name="prod", server="https://abc.gr7.us-east-1.eks.amazonaws.com")
        == ClusterProvider.EKS
    )


def test_detect_aks() -> None:
    assert (
        detect_provider(cluster_name="prod", server="https://prod-dns.hcp.eastus.azmk8s.io:443")
        == ClusterProvider.AKS
    )


def test_detect_gke_by_name() -> None:
    assert (
        detect_provider(cluster_name="gke_myproj_us-central1_prod", server="https://34.1.2.3")
        == ClusterProvider.GKE
    )


def test_detect_self_managed() -> None:
    assert (
        detect_provider(cluster_name="homelab", server="https://10.0.0.1:6443")
        == ClusterProvider.SELF_MANAGED
    )


def test_resolve_uses_current_context() -> None:
    cfg = _kubeconfig("gke_p_z_prod", "https://1.2.3.4")
    resolved = resolve_cluster(cfg)
    assert resolved.cluster_id == "gke_p_z_prod" and resolved.provider == ClusterProvider.GKE
    assert resolved.context == "ctx1"


def test_resolve_explicit_context() -> None:
    cfg = _kubeconfig("prod", "https://x.eks.amazonaws.com")
    assert resolve_cluster(cfg, context="ctx1").provider == ClusterProvider.EKS


def test_resolve_missing_context_raises() -> None:
    with pytest.raises(ClusterAuthError, match="not found"):
        resolve_cluster(_kubeconfig("prod", "https://x"), context="nope")


def test_resolve_no_current_context_raises() -> None:
    with pytest.raises(ClusterAuthError, match="no current-context"):
        resolve_cluster({"contexts": [], "clusters": []})


def test_resolve_missing_cluster_raises() -> None:
    cfg = {
        "current-context": "c",
        "contexts": [{"name": "c", "context": {"cluster": "ghost"}}],
        "clusters": [],
    }
    with pytest.raises(ClusterAuthError, match="cluster 'ghost' not found"):
        resolve_cluster(cfg)
