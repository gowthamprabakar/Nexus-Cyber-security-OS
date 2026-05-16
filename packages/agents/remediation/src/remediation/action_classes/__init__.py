"""Action classes for the Remediation Agent.

Each action class is a **pure-function pair**:

- `build(finding: ManifestFinding) -> RemediationArtifact` — generates the
  kubectl-patch payload that fixes the issue.
- `inverse(artifact: RemediationArtifact) -> RemediationArtifact` — generates
  the inverse patch that rolls the fix back.

All v0.1 action classes share the same `inverse` (`swap_for_inverse` from
`_common`), which swaps `patch_body` ↔ `inverse_patch_body`. Each builder
is responsible for emitting both the forward and the inverse leaf.

Execution happens in `tools/kubectl_executor.py` (Task 5); these classes
only describe the *what*, not the *how*.

The registry maps **D.6 `ManifestFinding.rule_id`** → action class. A
finding whose rule_id isn't in the registry is skipped at the AUTHZ stage
with a `RemediationOutcome.REFUSED_UNAUTHORIZED` audit entry.

**v0.1 scope** (5 classes; smallest blast-radius set):

| D.6 rule_id                    | Action class                                |
| ------------------------------ | ------------------------------------------- |
| `run-as-root`                  | `K8S_PATCH_RUN_AS_NON_ROOT`                 |
| `missing-resource-limits`      | `K8S_PATCH_RESOURCE_LIMITS`                 |
| `read-only-root-fs-missing`    | `K8S_PATCH_READ_ONLY_ROOT_FS`               |
| `image-pull-policy-not-always` | `K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS`        |
| `allow-privilege-escalation`   | `K8S_PATCH_DISABLE_PRIVILEGE_ESCALATION`    |

Deferred to v0.2+: `privileged-container`, `host-network`, `host-pid`,
`host-ipc`, `auto-mount-sa-token` (all too high blast-radius for v0.1
auto-remediation).
"""

from __future__ import annotations

from collections.abc import Callable

from k8s_posture.tools.manifests import ManifestFinding

from remediation.action_classes._common import swap_for_inverse
from remediation.action_classes.k8s_disable_privilege_escalation import (
    build_disable_privilege_escalation,
)
from remediation.action_classes.k8s_image_pull_policy_always import (
    build_image_pull_policy_always,
)
from remediation.action_classes.k8s_read_only_root_fs import build_read_only_root_fs
from remediation.action_classes.k8s_resource_limits import build_resource_limits
from remediation.action_classes.k8s_run_as_non_root import build_run_as_non_root
from remediation.schemas import RemediationActionType, RemediationArtifact

ActionBuilder = Callable[[ManifestFinding], RemediationArtifact]
ActionInverter = Callable[[RemediationArtifact], RemediationArtifact]


class ActionClass:
    """One v0.1 action class — a builder + its inverse, keyed by action type."""

    __slots__ = ("action_type", "build", "inverse")

    def __init__(
        self,
        *,
        action_type: RemediationActionType,
        build: ActionBuilder,
        inverse: ActionInverter,
    ) -> None:
        self.action_type = action_type
        self.build = build
        self.inverse = inverse


# Source D.6 rule_id → action class. All 5 v0.1 classes share `swap_for_inverse`
# as the inverter (the rollback patch is the artifact's pre-emitted
# inverse_patch_body).
ACTION_CLASS_REGISTRY: dict[str, ActionClass] = {
    "run-as-root": ActionClass(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        build=build_run_as_non_root,
        inverse=swap_for_inverse,
    ),
    "missing-resource-limits": ActionClass(
        action_type=RemediationActionType.K8S_PATCH_RESOURCE_LIMITS,
        build=build_resource_limits,
        inverse=swap_for_inverse,
    ),
    "read-only-root-fs-missing": ActionClass(
        action_type=RemediationActionType.K8S_PATCH_READ_ONLY_ROOT_FS,
        build=build_read_only_root_fs,
        inverse=swap_for_inverse,
    ),
    "image-pull-policy-not-always": ActionClass(
        action_type=RemediationActionType.K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS,
        build=build_image_pull_policy_always,
        inverse=swap_for_inverse,
    ),
    "allow-privilege-escalation": ActionClass(
        action_type=RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGE_ESCALATION,
        build=build_disable_privilege_escalation,
        inverse=swap_for_inverse,
    ),
}


def lookup_action_class(rule_id: str) -> ActionClass | None:
    """Return the action class for a D.6 `rule_id`, or None if no v0.1 fix exists."""
    return ACTION_CLASS_REGISTRY.get(rule_id)


__all__ = [
    "ACTION_CLASS_REGISTRY",
    "ActionBuilder",
    "ActionClass",
    "ActionInverter",
    "lookup_action_class",
]
