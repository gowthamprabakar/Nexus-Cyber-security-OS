"""Action class: `K8S_PATCH_RUN_AS_NON_ROOT` — fix `run-as-root` findings.

Sets the container's `securityContext.runAsNonRoot: true` and a default
`runAsUser: 65532` (the well-known nobody-equivalent UID in distroless
images). Container-level patch.

Inverse: removes both fields (strategic-merge-patch with `null`) — returns
the container to its pre-patch state.
"""

from __future__ import annotations

from k8s_posture.tools.manifests import ManifestFinding

from remediation.action_classes._common import (
    api_version_for,
    correlation_id_for,
    wrap_container_patch,
)
from remediation.schemas import RemediationActionType, RemediationArtifact

# A reserved UID — matches distroless / Google's chainguard images.
_RUN_AS_USER_NON_ROOT = 65532


def build_run_as_non_root(finding: ManifestFinding) -> RemediationArtifact:
    """Build the strategic-merge-patch that fixes `run-as-root`."""
    leaf = {
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": _RUN_AS_USER_NON_ROOT,
        }
    }
    inverse_leaf = {
        "securityContext": {
            "runAsNonRoot": None,
            "runAsUser": None,
        }
    }
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        api_version=api_version_for(finding.workload_kind),
        kind=finding.workload_kind,
        namespace=finding.namespace or "default",
        name=finding.workload_name,
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(finding, inverse_leaf),
        source_finding_uid=finding.rule_id,
        correlation_id=correlation_id_for(
            f"{finding.namespace}/{finding.workload_name}/{finding.container_name}/run-as-root"
        ),
    )
