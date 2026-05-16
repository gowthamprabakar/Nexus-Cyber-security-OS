"""Action class: `K8S_PATCH_DISABLE_PRIVILEGE_ESCALATION` — fix `allow-privilege-escalation`.

Sets the container's `securityContext.allowPrivilegeEscalation: false`.
Container-level patch.

Inverse: removes the field (defaults to `true` for non-CAP_NET_ADMIN
containers, `false` for restricted PSAs).
"""

from __future__ import annotations

from k8s_posture.tools.manifests import ManifestFinding

from remediation.action_classes._common import (
    api_version_for,
    correlation_id_for,
    wrap_container_patch,
)
from remediation.schemas import RemediationActionType, RemediationArtifact


def build_disable_privilege_escalation(finding: ManifestFinding) -> RemediationArtifact:
    """Build the strategic-merge-patch that disables privilege escalation."""
    leaf = {"securityContext": {"allowPrivilegeEscalation": False}}
    inverse_leaf = {"securityContext": {"allowPrivilegeEscalation": None}}
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGE_ESCALATION,
        api_version=api_version_for(finding.workload_kind),
        kind=finding.workload_kind,
        namespace=finding.namespace or "default",
        name=finding.workload_name,
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(finding, inverse_leaf),
        source_finding_uid=finding.rule_id,
        correlation_id=correlation_id_for(
            f"{finding.namespace}/{finding.workload_name}/{finding.container_name}/disable-privesc"
        ),
    )
