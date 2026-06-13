"""remediation v0.2 Task 9 — K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN action class (Q1)."""

from __future__ import annotations

from datetime import UTC, datetime

from k8s_posture.tools.manifests import ManifestFinding
from remediation.action_classes.k8s_disable_auto_mount_sa_token import (
    build_disable_auto_mount_sa_token,
)
from remediation.schemas import RemediationActionType

_NOW = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)


def _finding(*, workload_kind: str = "Deployment") -> ManifestFinding:
    return ManifestFinding(
        rule_id="auto-mount-sa-token",
        rule_title="Auto Mount SA Token",
        severity="medium",
        workload_kind=workload_kind,
        workload_name="api",
        namespace="prod",
        container_name="app",
        manifest_path="cluster:///prod/Deployment/api",
        detected_at=_NOW,
    )


def test_action_type() -> None:
    art = build_disable_auto_mount_sa_token(_finding())
    assert art.action_type == RemediationActionType.K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN
    assert (
        RemediationActionType.K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN.value
        == "remediation_k8s_patch_disable_auto_mount_sa_token"
    )


def test_patch_is_pod_spec_level() -> None:
    art = build_disable_auto_mount_sa_token(_finding())
    pod_spec = art.patch_body["spec"]["template"]["spec"]
    assert pod_spec["automountServiceAccountToken"] is False
    assert "containers" not in pod_spec


def test_inverse_restores_true() -> None:
    art = build_disable_auto_mount_sa_token(_finding())
    assert (
        art.inverse_patch_body["spec"]["template"]["spec"]["automountServiceAccountToken"] is True
    )


def test_pod_kind_uses_spec_directly() -> None:
    art = build_disable_auto_mount_sa_token(_finding(workload_kind="Pod"))
    assert art.patch_body["spec"]["automountServiceAccountToken"] is False


def test_correlation_derived() -> None:
    art = build_disable_auto_mount_sa_token(_finding())
    assert art.correlation_id.startswith("corr-")
    assert art.source_finding_uid == "auto-mount-sa-token"
