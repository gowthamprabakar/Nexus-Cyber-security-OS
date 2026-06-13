"""Phase C SS2 — resolve_cluster_context + run-flow single-cluster wiring (D.6/k8s-posture)."""

from __future__ import annotations

from pathlib import Path

import pytest
from k8s_posture.isolation import (
    CrossClusterContextError,
    assert_single_cluster_context,
    resolve_cluster_context,
)


def test_in_cluster_token() -> None:
    assert (
        resolve_cluster_context(in_cluster=True, kubeconfig=None, manifest_dir=None) == "in-cluster"
    )


def test_kubeconfig_token() -> None:
    kc = Path("/home/op/.kube/config")
    assert resolve_cluster_context(in_cluster=False, kubeconfig=kc, manifest_dir=None) == str(kc)


def test_manifest_dir_is_offline_none() -> None:
    assert (
        resolve_cluster_context(in_cluster=False, kubeconfig=None, manifest_dir=Path("/manifests"))
        is None
    )


def test_no_source_is_none() -> None:
    assert resolve_cluster_context(in_cluster=False, kubeconfig=None, manifest_dir=None) is None


def test_resolved_live_context_passes_single_cluster_assert() -> None:
    # The run-flow composition: a live source resolves to one context that the invariant accepts.
    ctx = resolve_cluster_context(in_cluster=True, kubeconfig=None, manifest_dir=None)
    assert ctx is not None
    assert assert_single_cluster_context([ctx]) == "in-cluster"


def test_multi_cluster_context_rejected() -> None:
    with pytest.raises(CrossClusterContextError, match="single-cluster"):
        assert_single_cluster_context(["cluster-a", "cluster-b"])
