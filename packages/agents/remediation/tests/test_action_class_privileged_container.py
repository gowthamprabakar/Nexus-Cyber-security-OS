"""remediation v0.2 Task 8 — K8S_PATCH_DISABLE_PRIVILEGED_CONTAINER action class (Q1)."""

from __future__ import annotations

from datetime import UTC, datetime

from k8s_posture.tools.manifests import ManifestFinding
from remediation.action_classes.k8s_disable_privileged_container import (
    build_disable_privileged_container,
)
from remediation.schemas import RemediationActionType

_NOW = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)


def _finding(
    *, workload_kind: str = "Deployment", container_name: str = "nginx"
) -> ManifestFinding:
    return ManifestFinding(
        rule_id="privileged-container",
        rule_title="Privileged Container",
        severity="high",
        workload_kind=workload_kind,
        workload_name="web",
        namespace="prod",
        container_name=container_name,
        manifest_path="cluster:///prod/Deployment/web",
        detected_at=_NOW,
    )


def test_action_type() -> None:
    art = build_disable_privileged_container(_finding())
    assert art.action_type == RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGED_CONTAINER
    assert (
        RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGED_CONTAINER.value
        == "remediation_k8s_patch_disable_privileged_container"
    )


def test_patch_sets_privileged_false() -> None:
    art = build_disable_privileged_container(_finding())
    container = art.patch_body["spec"]["template"]["spec"]["containers"][0]
    assert container["name"] == "nginx"
    assert container["securityContext"]["privileged"] is False


def test_inverse_restores_privileged_true() -> None:
    art = build_disable_privileged_container(_finding())
    container = art.inverse_patch_body["spec"]["template"]["spec"]["containers"][0]
    assert container["securityContext"]["privileged"] is True


def test_correlation_derived_from_finding() -> None:
    art = build_disable_privileged_container(_finding())
    assert art.correlation_id.startswith("corr-")
    assert art.source_finding_uid == "privileged-container"


def test_pod_kind_uses_spec_directly() -> None:
    art = build_disable_privileged_container(_finding(workload_kind="Pod"))
    container = art.patch_body["spec"]["containers"][0]
    assert container["securityContext"]["privileged"] is False
