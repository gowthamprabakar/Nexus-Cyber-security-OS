"""Tests for `remediation.action_classes` — the 5 v0.1 K8s patch classes."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from k8s_posture.tools.manifests import ManifestFinding
from remediation.action_classes import (
    ACTION_CLASS_REGISTRY,
    ActionClass,
    lookup_action_class,
)
from remediation.action_classes._common import (
    api_version_for,
    correlation_id_for,
    pod_spec_path_components,
    swap_for_inverse,
    wrap_container_patch,
    wrap_pod_spec_patch,
)

NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)


def _finding(
    *,
    rule_id: str = "run-as-root",
    severity: str = "high",
    workload_kind: str = "Deployment",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title=rule_id.replace("-", " ").title(),
        severity=severity,
        workload_kind=workload_kind,
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path="cluster:///production/Deployment/frontend",
        detected_at=NOW,
    )


# ---------------------------- registry composition ------------------------


def test_registry_has_5_action_classes() -> None:
    """v0.1 ships exactly 5 action classes."""
    assert len(ACTION_CLASS_REGISTRY) == 5


def test_registry_keys_are_d6_rule_ids() -> None:
    """The registry is keyed by D.6 ManifestFinding.rule_id strings."""
    expected = {
        "run-as-root",
        "missing-resource-limits",
        "read-only-root-fs-missing",
        "image-pull-policy-not-always",
        "allow-privilege-escalation",
    }
    assert set(ACTION_CLASS_REGISTRY) == expected


def test_registry_action_types_are_unique() -> None:
    """No two action classes share an action_type."""
    types = [ac.action_type for ac in ACTION_CLASS_REGISTRY.values()]
    assert len(types) == len(set(types))


def test_all_classes_share_the_same_inverse() -> None:
    """v0.1 inverse is uniform: swap patch_body ↔ inverse_patch_body."""
    for ac in ACTION_CLASS_REGISTRY.values():
        assert ac.inverse is swap_for_inverse


@pytest.mark.parametrize("rule_id", list(ACTION_CLASS_REGISTRY.keys()))
def test_lookup_returns_action_class_for_each_registered_rule(rule_id: str) -> None:
    ac = lookup_action_class(rule_id)
    assert isinstance(ac, ActionClass)
    assert ac.action_type == ACTION_CLASS_REGISTRY[rule_id].action_type


def test_lookup_returns_none_for_unknown_rule() -> None:
    """privileged-container is intentionally NOT in v0.1 (too high blast radius)."""
    assert lookup_action_class("privileged-container") is None
    assert lookup_action_class("host-network") is None
    assert lookup_action_class("totally-made-up-rule") is None


# ---------------------------- _common helpers -----------------------------


@pytest.mark.parametrize(
    "kind,expected_api_version",
    [
        ("Pod", "v1"),
        ("Deployment", "apps/v1"),
        ("StatefulSet", "apps/v1"),
        ("DaemonSet", "apps/v1"),
        ("ReplicaSet", "apps/v1"),
        ("Job", "batch/v1"),
        ("CronJob", "batch/v1"),
        ("SomeWeirdKind", "v1"),  # fallback
    ],
)
def test_api_version_for_workload_kinds(kind: str, expected_api_version: str) -> None:
    assert api_version_for(kind) == expected_api_version


def test_correlation_id_is_deterministic() -> None:
    """Same source UID → same correlation_id (idempotency primitive)."""
    cid_1 = correlation_id_for("REM-K8S-001-test")
    cid_2 = correlation_id_for("REM-K8S-001-test")
    assert cid_1 == cid_2


def test_correlation_id_differs_for_different_sources() -> None:
    cid_1 = correlation_id_for("REM-K8S-001-test")
    cid_2 = correlation_id_for("REM-K8S-002-different")
    assert cid_1 != cid_2


def test_correlation_id_format() -> None:
    cid = correlation_id_for("anything")
    assert cid.startswith("corr-")
    # 5 chars for "corr-" + 16 chars for hex digest = 21
    assert len(cid) == 21


@pytest.mark.parametrize(
    "kind,expected_path",
    [
        ("Pod", ["spec"]),
        ("Deployment", ["spec", "template", "spec"]),
        ("StatefulSet", ["spec", "template", "spec"]),
        ("Job", ["spec", "template", "spec"]),
        ("CronJob", ["spec", "jobTemplate", "spec", "template", "spec"]),
    ],
)
def test_pod_spec_path_components(kind: str, expected_path: list[str]) -> None:
    finding = _finding(workload_kind=kind)
    assert pod_spec_path_components(finding) == expected_path


def test_wrap_pod_spec_patch_for_deployment() -> None:
    finding = _finding(workload_kind="Deployment")
    leaf = {"hostNetwork": True}
    result = wrap_pod_spec_patch(finding, leaf)
    assert result == {"spec": {"template": {"spec": {"hostNetwork": True}}}}


def test_wrap_pod_spec_patch_for_pod() -> None:
    finding = _finding(workload_kind="Pod")
    leaf = {"hostNetwork": True}
    result = wrap_pod_spec_patch(finding, leaf)
    assert result == {"spec": {"hostNetwork": True}}


def test_wrap_pod_spec_patch_for_cronjob() -> None:
    finding = _finding(workload_kind="CronJob")
    leaf = {"hostNetwork": True}
    result = wrap_pod_spec_patch(finding, leaf)
    assert result == {
        "spec": {"jobTemplate": {"spec": {"template": {"spec": {"hostNetwork": True}}}}}
    }


def test_wrap_container_patch_uses_name_as_merge_key() -> None:
    finding = _finding(workload_kind="Deployment", container_name="nginx")
    fields = {"imagePullPolicy": "Always"}
    result = wrap_container_patch(finding, fields)
    containers = result["spec"]["template"]["spec"]["containers"]  # type: ignore[index]
    assert len(containers) == 1
    assert containers[0]["name"] == "nginx"
    assert containers[0]["imagePullPolicy"] == "Always"


def test_wrap_container_patch_requires_container_name() -> None:
    """A finding without a container_name can't be patched at the container level."""
    finding = _finding(container_name="")
    with pytest.raises(ValueError, match="no container_name"):
        wrap_container_patch(finding, {"imagePullPolicy": "Always"})


# ---------------------------- swap_for_inverse ----------------------------


def test_swap_for_inverse_swaps_patches() -> None:
    """The inverse-of-inverse is the original patch (modulo correlation_id suffix)."""
    finding = _finding()
    ac = ACTION_CLASS_REGISTRY["run-as-root"]
    artifact = ac.build(finding)
    rollback = swap_for_inverse(artifact)
    # The forward patch becomes the inverse, and vice versa.
    assert rollback.patch_body == artifact.inverse_patch_body
    assert rollback.inverse_patch_body == artifact.patch_body
    # Correlation id carries the rollback suffix.
    assert rollback.correlation_id == artifact.correlation_id + "-rollback"
    # All other fields preserved.
    assert rollback.action_type == artifact.action_type
    assert rollback.api_version == artifact.api_version
    assert rollback.kind == artifact.kind
    assert rollback.namespace == artifact.namespace
    assert rollback.name == artifact.name


# ---------------------------- per-action-class shape ---------------------


def test_run_as_non_root_sets_runAsNonRoot_true() -> None:
    finding = _finding(rule_id="run-as-root")
    ac = ACTION_CLASS_REGISTRY["run-as-root"]
    artifact = ac.build(finding)
    container = artifact.patch_body["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
    assert container["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["runAsUser"] == 65532


def test_run_as_non_root_inverse_removes_fields() -> None:
    finding = _finding(rule_id="run-as-root")
    ac = ACTION_CLASS_REGISTRY["run-as-root"]
    artifact = ac.build(finding)
    container = artifact.inverse_patch_body["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
    assert container["securityContext"]["runAsNonRoot"] is None
    assert container["securityContext"]["runAsUser"] is None


def test_resource_limits_sets_baseline_cpu_memory() -> None:
    finding = _finding(rule_id="missing-resource-limits")
    ac = ACTION_CLASS_REGISTRY["missing-resource-limits"]
    artifact = ac.build(finding)
    container = artifact.patch_body["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
    assert container["resources"]["limits"]["cpu"] == "500m"
    assert container["resources"]["limits"]["memory"] == "256Mi"


def test_resource_limits_inverse_removes_limits() -> None:
    finding = _finding(rule_id="missing-resource-limits")
    ac = ACTION_CLASS_REGISTRY["missing-resource-limits"]
    artifact = ac.build(finding)
    container = artifact.inverse_patch_body["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
    assert container["resources"]["limits"] is None


def test_read_only_root_fs_sets_true() -> None:
    finding = _finding(rule_id="read-only-root-fs-missing")
    ac = ACTION_CLASS_REGISTRY["read-only-root-fs-missing"]
    artifact = ac.build(finding)
    container = artifact.patch_body["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True


def test_image_pull_policy_sets_always() -> None:
    finding = _finding(rule_id="image-pull-policy-not-always")
    ac = ACTION_CLASS_REGISTRY["image-pull-policy-not-always"]
    artifact = ac.build(finding)
    container = artifact.patch_body["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
    assert container["imagePullPolicy"] == "Always"


def test_disable_privilege_escalation_sets_false() -> None:
    finding = _finding(rule_id="allow-privilege-escalation")
    ac = ACTION_CLASS_REGISTRY["allow-privilege-escalation"]
    artifact = ac.build(finding)
    container = artifact.patch_body["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
    assert container["securityContext"]["allowPrivilegeEscalation"] is False


# ---------------------------- target reference ----------------------------


def test_artifact_target_matches_finding_namespace_and_name() -> None:
    finding = _finding(namespace="staging", workload_name="cache")
    artifact = ACTION_CLASS_REGISTRY["run-as-root"].build(finding)
    assert artifact.namespace == "staging"
    assert artifact.name == "cache"


def test_artifact_api_version_matches_workload_kind() -> None:
    finding = _finding(workload_kind="CronJob")
    artifact = ACTION_CLASS_REGISTRY["run-as-root"].build(finding)
    assert artifact.api_version == "batch/v1"
    assert artifact.kind == "CronJob"


# ---------------------------- idempotency contract ------------------------


def test_same_finding_produces_same_correlation_id() -> None:
    """Re-running A.1 on the same finding should produce the same artifact (no
    double-apply). The correlation_id is derived deterministically from the
    finding's namespace/workload/container/rule context."""
    finding_1 = _finding(rule_id="run-as-root")
    finding_2 = _finding(rule_id="run-as-root")  # identical content
    artifact_1 = ACTION_CLASS_REGISTRY["run-as-root"].build(finding_1)
    artifact_2 = ACTION_CLASS_REGISTRY["run-as-root"].build(finding_2)
    assert artifact_1.correlation_id == artifact_2.correlation_id


def test_different_containers_get_different_correlation_ids() -> None:
    """Patching `nginx` and `sidecar` containers in the same workload should be
    distinguishable in the audit chain."""
    nginx = _finding(rule_id="run-as-root", container_name="nginx")
    sidecar = _finding(rule_id="run-as-root", container_name="sidecar")
    a_nginx = ACTION_CLASS_REGISTRY["run-as-root"].build(nginx)
    a_sidecar = ACTION_CLASS_REGISTRY["run-as-root"].build(sidecar)
    assert a_nginx.correlation_id != a_sidecar.correlation_id


# ---------------------------- patch strategy ------------------------------


def test_all_v0_1_actions_use_strategic_merge_patch() -> None:
    """v0.1 ships strategic-merge-patch only — it's the safest for container
    list updates (uses `name` as the merge key automatically)."""
    for rule_id, ac in ACTION_CLASS_REGISTRY.items():
        artifact = ac.build(_finding(rule_id=rule_id))
        assert artifact.patch_strategy == "strategic"
