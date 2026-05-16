"""Shared helpers for action classes.

Includes `wrap_pod_spec_patch` and `wrap_container_patch` — both produce
strategic-merge-patch bodies suitable for `kubectl patch --type=strategic`.

Also `swap_for_inverse` — the shared inverter used by every v0.1 action
class (the rollback patch is always just the artifact's
`inverse_patch_body` applied as the `patch_body`, with patch/inverse
swapped so re-applying is a no-op).


The 5 v0.1 action classes share boilerplate:

- mapping a `ManifestFinding`'s `workload_kind` to its K8s `api_version`
- generating the deterministic `correlation_id` from the source finding
- building the `target` block (api_version + kind + namespace + name)

Kept private to the `action_classes` subpackage; not part of the public API.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from k8s_posture.tools.manifests import ManifestFinding

from remediation.schemas import RemediationArtifact

# K8s workload kind → API group/version mapping (matches what kubectl uses).
_KIND_TO_API_VERSION: dict[str, str] = {
    "Pod": "v1",
    "Deployment": "apps/v1",
    "StatefulSet": "apps/v1",
    "DaemonSet": "apps/v1",
    "ReplicaSet": "apps/v1",
    "Job": "batch/v1",
    "CronJob": "batch/v1",
}


def api_version_for(kind: str) -> str:
    """Return the K8s API version for a workload kind. Defaults to `v1` for unknowns."""
    return _KIND_TO_API_VERSION.get(kind, "v1")


def correlation_id_for(finding_uid: str) -> str:
    """Deterministic correlation ID derived from the source finding UID.

    Idempotency: re-running A.1 on the same finding produces the same artifact
    (same correlation_id) — preventing double-apply.
    """
    digest = hashlib.sha256(finding_uid.encode("utf-8")).hexdigest()[:16]
    return f"corr-{digest}"


def is_pod(finding: ManifestFinding) -> bool:
    """Workloads with `kind: Pod` use `spec.*` directly; everything else uses
    `spec.template.spec.*` (or `spec.jobTemplate.spec.template.spec.*` for CronJob)."""
    return finding.workload_kind == "Pod"


def is_cronjob(finding: ManifestFinding) -> bool:
    return finding.workload_kind == "CronJob"


def pod_spec_path_components(finding: ManifestFinding) -> list[str]:
    """Return the dotted path from the manifest root to the pod-spec.

    - `Pod`            → ['spec']
    - `Deployment` (and friends) → ['spec', 'template', 'spec']
    - `CronJob`        → ['spec', 'jobTemplate', 'spec', 'template', 'spec']
    """
    if is_pod(finding):
        return ["spec"]
    if is_cronjob(finding):
        return ["spec", "jobTemplate", "spec", "template", "spec"]
    return ["spec", "template", "spec"]


def wrap_pod_spec_patch(
    finding: ManifestFinding,
    leaf: Mapping[str, Any],
) -> dict[str, Any]:
    """Wrap a pod-spec-level dict in the right outer structure for the workload kind.

    Example:
        wrap_pod_spec_patch(<Deployment finding>, {"securityContext": {"runAsNonRoot": True}})
        # → {"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": True}}}}}
    """
    body: dict[str, Any] = dict(leaf)
    for component in reversed(pod_spec_path_components(finding)):
        body = {component: body}
    return body


def wrap_container_patch(
    finding: ManifestFinding,
    container_fields: Mapping[str, Any],
) -> dict[str, Any]:
    """Wrap a container-level patch in the strategic-merge-patch shape K8s expects.

    Strategic-merge-patch on `containers` uses `name` as the merge key — the
    patched container must include its `name` field so K8s knows which list
    item to update. Pod-level `host*` flags are not container-level.

    Example:
        wrap_container_patch(<Deployment finding for nginx>,
                              {"securityContext": {"runAsNonRoot": True}})
        # → {"spec": {"template": {"spec": {"containers": [{"name": "nginx",
        #     "securityContext": {"runAsNonRoot": True}}]}}}}
    """
    if not finding.container_name:
        raise ValueError(
            f"finding for rule_id={finding.rule_id!r} has no container_name; "
            "container-level patches require an identified container"
        )
    container_patch: dict[str, Any] = {"name": finding.container_name, **container_fields}
    return wrap_pod_spec_patch(finding, {"containers": [container_patch]})


def swap_for_inverse(artifact: RemediationArtifact) -> RemediationArtifact:
    """Shared inverter — swap `patch_body` ↔ `inverse_patch_body`.

    Applied during rollback when post-validation fails. Re-applying the
    result (i.e. applying `swap_for_inverse(swap_for_inverse(a))`) is a
    no-op — `patch_body == a.patch_body` again. Deterministic; pure.
    """
    return RemediationArtifact(
        action_type=artifact.action_type,
        api_version=artifact.api_version,
        kind=artifact.kind,
        namespace=artifact.namespace,
        name=artifact.name,
        patch_strategy=artifact.patch_strategy,
        patch_body=artifact.inverse_patch_body,
        inverse_patch_body=artifact.patch_body,
        source_finding_uid=artifact.source_finding_uid,
        correlation_id=artifact.correlation_id + "-rollback",
    )
