"""Action class: `K8S_PATCH_DISABLE_PRIVILEGED_CONTAINER` — fix `privileged-container` findings.

Sets the container's ``securityContext.privileged: false`` (a privileged container has
near-host-root capabilities). Container-level strategic-merge patch. Inverse restores
``privileged: true`` for rollback.

⚠️ v0.2 (Cycle 16): this is a **privileged action** — disabling privileged mode can break a
workload that legitimately needs host capabilities, so it requires EXTRA authorization
(``privileged_actions_authorized: true`` in auth.yaml) beyond the standard allowlist. That guard
is ``invariants.assert_privileged_action_extra_authz`` (Task 15, WI-A16); this module only builds
the patch.
"""

from __future__ import annotations

from k8s_posture.tools.manifests import ManifestFinding

from remediation.action_classes._common import (
    api_version_for,
    correlation_id_for,
    wrap_container_patch,
)
from remediation.schemas import RemediationActionType, RemediationArtifact


def build_disable_privileged_container(finding: ManifestFinding) -> RemediationArtifact:
    """Build the strategic-merge-patch that disables a privileged container."""
    leaf = {"securityContext": {"privileged": False}}
    inverse_leaf = {"securityContext": {"privileged": True}}
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGED_CONTAINER,
        api_version=api_version_for(finding.workload_kind),
        kind=finding.workload_kind,
        namespace=finding.namespace or "default",
        name=finding.workload_name,
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(finding, inverse_leaf),
        source_finding_uid=finding.rule_id,
        correlation_id=correlation_id_for(
            f"{finding.namespace}/{finding.workload_name}/{finding.container_name}/privileged"
        ),
    )
