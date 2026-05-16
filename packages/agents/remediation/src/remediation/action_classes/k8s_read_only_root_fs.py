"""Action class: `K8S_PATCH_READ_ONLY_ROOT_FS` — fix `read-only-root-fs-missing`.

Sets the container's `securityContext.readOnlyRootFilesystem: true`.
Container-level patch.

Inverse: removes the field (strategic-merge-patch with `null`).
"""

from __future__ import annotations

from k8s_posture.tools.manifests import ManifestFinding

from remediation.action_classes._common import (
    api_version_for,
    correlation_id_for,
    wrap_container_patch,
)
from remediation.schemas import RemediationActionType, RemediationArtifact


def build_read_only_root_fs(finding: ManifestFinding) -> RemediationArtifact:
    """Build the strategic-merge-patch that sets readOnlyRootFilesystem: true."""
    leaf = {"securityContext": {"readOnlyRootFilesystem": True}}
    inverse_leaf = {"securityContext": {"readOnlyRootFilesystem": None}}
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_READ_ONLY_ROOT_FS,
        api_version=api_version_for(finding.workload_kind),
        kind=finding.workload_kind,
        namespace=finding.namespace or "default",
        name=finding.workload_name,
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(finding, inverse_leaf),
        source_finding_uid=finding.rule_id,
        correlation_id=correlation_id_for(
            f"{finding.namespace}/{finding.workload_name}/{finding.container_name}/read-only-root-fs"
        ),
    )
