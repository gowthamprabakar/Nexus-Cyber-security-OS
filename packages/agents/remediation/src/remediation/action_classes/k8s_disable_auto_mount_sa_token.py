"""Action class: `K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN` — fix `auto-mount-sa-token` findings.

Sets ``automountServiceAccountToken: false`` on the **pod spec** (an auto-mounted SA token is a
credential a compromised container can use against the API server). Pod-spec-level strategic-merge
patch. Inverse restores ``automountServiceAccountToken: true`` for rollback.

⚠️ v0.2 (Cycle 16): disabling auto-mount **breaks** a workload that actively consumes the token,
so it requires a pre-validation that no active token consumer is present — enforced by
``invariants.assert_auto_mount_validation`` (Task 16, WI-A17); this module only builds the patch.
"""

from __future__ import annotations

from k8s_posture.tools.manifests import ManifestFinding

from remediation.action_classes._common import (
    api_version_for,
    correlation_id_for,
    wrap_pod_spec_patch,
)
from remediation.schemas import RemediationActionType, RemediationArtifact


def build_disable_auto_mount_sa_token(finding: ManifestFinding) -> RemediationArtifact:
    """Build the strategic-merge-patch that disables SA-token auto-mount on the pod spec."""
    leaf = {"automountServiceAccountToken": False}
    inverse_leaf = {"automountServiceAccountToken": True}
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN,
        api_version=api_version_for(finding.workload_kind),
        kind=finding.workload_kind,
        namespace=finding.namespace or "default",
        name=finding.workload_name,
        patch_strategy="strategic",
        patch_body=wrap_pod_spec_patch(finding, leaf),
        inverse_patch_body=wrap_pod_spec_patch(finding, inverse_leaf),
        source_finding_uid=finding.rule_id,
        correlation_id=correlation_id_for(
            f"{finding.namespace}/{finding.workload_name}/auto-mount-sa-token"
        ),
    )
