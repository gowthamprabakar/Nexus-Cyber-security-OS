"""Action class: `K8S_PATCH_RESOURCE_LIMITS` — fix `missing-resource-limits` findings.

Sets baseline `resources.limits.cpu: 500m` + `resources.limits.memory: 256Mi`
on the container. Container-level patch.

The defaults are conservative starting values — operators are expected to
tune them based on actual workload telemetry. The point of the action is to
*establish* limits where none existed, not to optimise them.

Inverse: removes the `resources.limits` block entirely.
"""

from __future__ import annotations

from k8s_posture.tools.manifests import ManifestFinding

from remediation.action_classes._common import (
    api_version_for,
    correlation_id_for,
    wrap_container_patch,
)
from remediation.schemas import RemediationActionType, RemediationArtifact

# Conservative baseline limits — operators are expected to tune.
_DEFAULT_CPU_LIMIT = "500m"
_DEFAULT_MEMORY_LIMIT = "256Mi"


def build_resource_limits(finding: ManifestFinding) -> RemediationArtifact:
    """Build the strategic-merge-patch that adds resource limits."""
    leaf = {
        "resources": {
            "limits": {
                "cpu": _DEFAULT_CPU_LIMIT,
                "memory": _DEFAULT_MEMORY_LIMIT,
            }
        }
    }
    inverse_leaf = {
        "resources": {
            "limits": None,
        }
    }
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_RESOURCE_LIMITS,
        api_version=api_version_for(finding.workload_kind),
        kind=finding.workload_kind,
        namespace=finding.namespace or "default",
        name=finding.workload_name,
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(finding, inverse_leaf),
        source_finding_uid=finding.rule_id,
        correlation_id=correlation_id_for(
            f"{finding.namespace}/{finding.workload_name}/{finding.container_name}/resource-limits"
        ),
    )
