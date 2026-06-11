"""D.6 v0.2 Task 14 — per-cluster scan-context isolation tests (Q3/WI-K8 invariant)."""

from __future__ import annotations

import pytest
from k8s_posture.isolation import (
    ClusterScanSession,
    CrossClusterContextError,
    assert_single_cluster_context,
)


def test_single_cluster_ok() -> None:
    assert assert_single_cluster_context(["eks-prod", "eks-prod"]) == "eks-prod"


def test_multiple_clusters_raises() -> None:
    with pytest.raises(CrossClusterContextError, match="single-cluster only"):
        assert_single_cluster_context(["eks-prod", "aks-dev"])


def test_empty_context_raises() -> None:
    with pytest.raises(CrossClusterContextError, match="no cluster context"):
        assert_single_cluster_context([])


def test_empty_id_raises() -> None:
    with pytest.raises(CrossClusterContextError, match="empty cluster id"):
        assert_single_cluster_context(["eks-prod", ""])


def test_session_binds_cluster() -> None:
    session = ClusterScanSession("gke-staging")
    assert session.cluster_id == "gke-staging"


def test_session_empty_cluster_raises() -> None:
    with pytest.raises(CrossClusterContextError, match="non-empty"):
        ClusterScanSession("")


def test_assert_belongs_same_cluster_ok() -> None:
    ClusterScanSession("eks-prod").assert_belongs("eks-prod")  # no raise


def test_assert_belongs_cross_cluster_raises() -> None:
    session = ClusterScanSession("eks-prod")
    with pytest.raises(CrossClusterContextError, match="cross-cluster context leak"):
        session.assert_belongs("aks-dev")
