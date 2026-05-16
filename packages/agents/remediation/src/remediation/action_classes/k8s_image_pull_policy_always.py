"""Action class: `K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS` — fix `image-pull-policy-not-always`.

Sets the container's `imagePullPolicy: Always`. Container-level patch.

This is the lowest-blast-radius v0.1 action — `Always` is the safe-default
imagePullPolicy across all K8s versions and never breaks a workload.

Inverse: removes the field (defaults to `IfNotPresent` for tagged images,
`Always` for `:latest`).
"""

from __future__ import annotations

from k8s_posture.tools.manifests import ManifestFinding

from remediation.action_classes._common import (
    api_version_for,
    correlation_id_for,
    wrap_container_patch,
)
from remediation.schemas import RemediationActionType, RemediationArtifact


def build_image_pull_policy_always(finding: ManifestFinding) -> RemediationArtifact:
    """Build the strategic-merge-patch that sets imagePullPolicy: Always."""
    leaf = {"imagePullPolicy": "Always"}
    inverse_leaf = {"imagePullPolicy": None}
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS,
        api_version=api_version_for(finding.workload_kind),
        kind=finding.workload_kind,
        namespace=finding.namespace or "default",
        name=finding.workload_name,
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(finding, inverse_leaf),
        source_finding_uid=finding.rule_id,
        correlation_id=correlation_id_for(
            f"{finding.namespace}/{finding.workload_name}/{finding.container_name}/image-pull-policy"
        ),
    )
