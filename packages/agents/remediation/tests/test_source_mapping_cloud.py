"""remediation v0.2 Task 12 — F.3 + D.5 cloud-K8s source mapping (Q3/WI-A1)."""

from __future__ import annotations

from remediation.tools.source_mapping import (
    SOURCE_RULE_MAP,
    actionable_rule_ids_for,
    is_actionable,
)


def test_three_k8s_relevant_sources() -> None:
    # Q3: k8s-posture (D.6) + cloud_posture (F.3 EKS) + multi_cloud_posture (D.5 AKS/GKE).
    assert set(SOURCE_RULE_MAP) == {"k8s_posture", "cloud_posture", "multi_cloud_posture"}


def test_cloud_workload_finding_is_actionable() -> None:
    # an EKS/AKS workload finding carrying a canonical rule_id is remediable.
    assert is_actionable("cloud_posture", "run-as-root")
    assert is_actionable("multi_cloud_posture", "privileged-container")


def test_cloud_control_plane_finding_not_actionable() -> None:
    # a cluster/control-plane cloud finding matches no action class (honest WI-A3).
    assert not is_actionable("cloud_posture", "eks-public-endpoint")
    assert not is_actionable("multi_cloud_posture", "aks-no-rbac")


def test_each_source_tracked_separately() -> None:
    # WI-A1: per-source, not an aggregate.
    assert actionable_rule_ids_for("cloud_posture") == actionable_rule_ids_for("k8s_posture")
    assert actionable_rule_ids_for("network_threat") == frozenset()  # not a K8s source
