"""Tests for `k8s_posture.tools.manifests` — the 10-rule analyser."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from k8s_posture.schemas import Severity
from k8s_posture.tools.manifests import ManifestReaderError, read_manifests


def _write_manifest(tmp_path: Path, name: str, manifest: dict[str, Any]) -> Path:
    """Write a single-document YAML manifest to tmp_path/name.yaml."""
    p = tmp_path / f"{name}.yaml"
    p.write_text(yaml.safe_dump(manifest))
    return p


def _pod(*, container: dict[str, Any], **pod_spec_overrides: Any) -> dict[str, Any]:
    """Build a minimal Pod manifest."""
    spec: dict[str, Any] = {"containers": [container]}
    spec.update(pod_spec_overrides)
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "my-pod", "namespace": "production"},
        "spec": spec,
    }


def _deployment(*, container: dict[str, Any], **pod_spec_overrides: Any) -> dict[str, Any]:
    """Build a minimal Deployment manifest with the given container."""
    pod_spec: dict[str, Any] = {"containers": [container]}
    pod_spec.update(pod_spec_overrides)
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "frontend", "namespace": "production"},
        "spec": {
            "replicas": 1,
            "template": {"spec": pod_spec},
        },
    }


def _safe_container(*, name: str = "nginx") -> dict[str, Any]:
    """A container that passes all 10 rules — for testing missing-fields → finding."""
    return {
        "name": name,
        "image": "nginx:1.27",
        "imagePullPolicy": "Always",
        "securityContext": {
            "runAsUser": 1000,
            "privileged": False,
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
        },
        "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
    }


# ---------------------------- file / directory handling ------------------


@pytest.mark.asyncio
async def test_missing_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(ManifestReaderError, match="not found"):
        await read_manifests(path=tmp_path / "missing")


@pytest.mark.asyncio
async def test_path_is_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "file.yaml"
    p.write_text("")
    with pytest.raises(ManifestReaderError, match="not a directory"):
        await read_manifests(path=p)


@pytest.mark.asyncio
async def test_empty_dir_returns_empty(tmp_path: Path) -> None:
    out = await read_manifests(path=tmp_path)
    assert out == ()


@pytest.mark.asyncio
async def test_yml_extension_also_picked_up(tmp_path: Path) -> None:
    """Both .yaml and .yml files are walked."""
    pod = _pod(container=_safe_container())
    # Force a finding by making the container unsafe.
    pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
    p = tmp_path / "manifest.yml"
    p.write_text(yaml.safe_dump(pod))

    out = await read_manifests(path=tmp_path)
    assert any(f.rule_id == "privileged-container" for f in out)


@pytest.mark.asyncio
async def test_malformed_yaml_skipped(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: valid: yaml: : :")
    good = _pod(container=_safe_container())
    good["spec"]["hostNetwork"] = True  # one finding
    _write_manifest(tmp_path, "good", good)

    out = await read_manifests(path=tmp_path)
    assert any(f.rule_id == "host-network" for f in out)


@pytest.mark.asyncio
async def test_non_dict_yaml_doc_skipped(tmp_path: Path) -> None:
    (tmp_path / "scalar.yaml").write_text("just a string")
    out = await read_manifests(path=tmp_path)
    assert out == ()


# ---------------------------- supported kinds ----------------------------


@pytest.mark.parametrize(
    "kind",
    ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"],
)
@pytest.mark.asyncio
async def test_pod_template_kinds_walked(tmp_path: Path, kind: str) -> None:
    """All standard pod-template-bearing kinds are walked."""
    manifest = _deployment(container=_safe_container())
    manifest["kind"] = kind
    manifest["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = True
    _write_manifest(tmp_path, "wkl", manifest)

    out = await read_manifests(path=tmp_path)
    assert any(f.rule_id == "privileged-container" for f in out)


@pytest.mark.asyncio
async def test_pod_kind_walked(tmp_path: Path) -> None:
    pod = _pod(container=_safe_container())
    pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert len(out) >= 1
    assert out[0].workload_kind == "Pod"


@pytest.mark.asyncio
async def test_cronjob_walked(tmp_path: Path) -> None:
    cron = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "backup", "namespace": "default"},
        "spec": {
            "schedule": "0 0 * * *",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [_safe_container()],
                            "hostNetwork": True,  # force a finding
                        }
                    }
                }
            },
        },
    }
    _write_manifest(tmp_path, "cron", cron)
    out = await read_manifests(path=tmp_path)
    assert any(f.rule_id == "host-network" for f in out)


@pytest.mark.asyncio
async def test_irrelevant_kinds_skipped(tmp_path: Path) -> None:
    """Service / Ingress / ConfigMap don't carry pod posture; silently skipped."""
    svc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "frontend"},
        "spec": {"selector": {"app": "frontend"}, "ports": [{"port": 80}]},
    }
    _write_manifest(tmp_path, "svc", svc)
    out = await read_manifests(path=tmp_path)
    assert out == ()


# ---------------------------- individual rules ---------------------------


@pytest.mark.asyncio
async def test_run_as_root_fires_when_runasuser_zero(tmp_path: Path) -> None:
    pod = _pod(container=_safe_container())
    pod["spec"]["containers"][0]["securityContext"]["runAsUser"] = 0
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert any(f.rule_id == "run-as-root" and f.severity == Severity.HIGH for f in out)


@pytest.mark.asyncio
async def test_run_as_root_fires_when_securitycontext_missing(tmp_path: Path) -> None:
    """No securityContext at all → root by default → finding."""
    container = {
        "name": "nginx",
        "image": "nginx:1.27",
        "imagePullPolicy": "Always",
        "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}},
    }
    pod = _pod(container=container)
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert any(f.rule_id == "run-as-root" for f in out)


@pytest.mark.asyncio
async def test_privileged_container_fires(tmp_path: Path) -> None:
    pod = _pod(container=_safe_container())
    pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    findings = [f for f in out if f.rule_id == "privileged-container"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_host_network_pid_ipc_fire(tmp_path: Path) -> None:
    pod = _pod(
        container=_safe_container(),
        hostNetwork=True,
        hostPID=True,
        hostIPC=True,
    )
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    rule_ids = {f.rule_id for f in out}
    assert "host-network" in rule_ids
    assert "host-pid" in rule_ids
    assert "host-ipc" in rule_ids


@pytest.mark.asyncio
async def test_missing_resource_limits_fires(tmp_path: Path) -> None:
    container = _safe_container()
    container["resources"] = {}  # no limits
    pod = _pod(container=container)
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert any(
        f.rule_id == "missing-resource-limits" and f.severity == Severity.MEDIUM for f in out
    )


@pytest.mark.asyncio
async def test_missing_resource_limits_partial(tmp_path: Path) -> None:
    """Has cpu limit but no memory → still fires."""
    container = _safe_container()
    container["resources"] = {"limits": {"cpu": "100m"}}  # memory missing
    pod = _pod(container=container)
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert any(f.rule_id == "missing-resource-limits" for f in out)


@pytest.mark.asyncio
async def test_image_pull_policy_not_always_fires(tmp_path: Path) -> None:
    container = _safe_container()
    container["imagePullPolicy"] = "IfNotPresent"
    pod = _pod(container=container)
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert any(
        f.rule_id == "image-pull-policy-not-always" and f.severity == Severity.MEDIUM for f in out
    )


@pytest.mark.asyncio
async def test_image_pull_policy_missing_fires(tmp_path: Path) -> None:
    """imagePullPolicy absent → finding (not implicitly Always)."""
    container = _safe_container()
    del container["imagePullPolicy"]
    pod = _pod(container=container)
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert any(f.rule_id == "image-pull-policy-not-always" for f in out)


@pytest.mark.asyncio
async def test_allow_privilege_escalation_fires(tmp_path: Path) -> None:
    pod = _pod(container=_safe_container())
    pod["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"] = True
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert any(
        f.rule_id == "allow-privilege-escalation" and f.severity == Severity.HIGH for f in out
    )


@pytest.mark.asyncio
async def test_read_only_root_fs_fires_when_missing(tmp_path: Path) -> None:
    pod = _pod(container=_safe_container())
    pod["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] = False
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert any(
        f.rule_id == "read-only-root-fs-missing" and f.severity == Severity.MEDIUM for f in out
    )


@pytest.mark.asyncio
async def test_auto_mount_sa_token_fires_when_not_false(tmp_path: Path) -> None:
    """Default (no setting) → finding. Explicit false → no finding."""
    pod = _pod(container=_safe_container())
    # Default state: no automountServiceAccountToken key → fires
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert any(f.rule_id == "auto-mount-sa-token" for f in out)


@pytest.mark.asyncio
async def test_auto_mount_sa_token_silent_when_explicit_false(tmp_path: Path) -> None:
    pod = _pod(container=_safe_container(), automountServiceAccountToken=False)
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    assert not any(f.rule_id == "auto-mount-sa-token" for f in out)


# ---------------------------- safe manifest ------------------------------


@pytest.mark.asyncio
async def test_fully_safe_manifest_emits_no_findings(tmp_path: Path) -> None:
    """A pod with all best-practice security context + resource limits + automount=false."""
    pod = _pod(container=_safe_container(), automountServiceAccountToken=False)
    _write_manifest(tmp_path, "safe", pod)

    out = await read_manifests(path=tmp_path)
    assert out == ()


# ---------------------------- multiple workloads / docs -----------------


@pytest.mark.asyncio
async def test_multiple_files_each_analysed(tmp_path: Path) -> None:
    p1 = _pod(container=_safe_container())
    p1["metadata"]["name"] = "p1"
    p1["spec"]["containers"][0]["securityContext"]["privileged"] = True
    _write_manifest(tmp_path, "p1", p1)

    p2 = _pod(container=_safe_container())
    p2["metadata"]["name"] = "p2"
    p2["spec"]["hostNetwork"] = True
    _write_manifest(tmp_path, "p2", p2)

    out = await read_manifests(path=tmp_path)
    workload_names = {f.workload_name for f in out}
    assert workload_names == {"p1", "p2"}


@pytest.mark.asyncio
async def test_multi_document_yaml(tmp_path: Path) -> None:
    """`---` separated multi-doc YAML — all docs walked."""
    pod_a = yaml.safe_dump(_pod(container=_safe_container()))
    pod_b_raw = _pod(container=_safe_container())
    pod_b_raw["metadata"]["name"] = "pod-b"
    pod_b_raw["spec"]["hostNetwork"] = True
    pod_b = yaml.safe_dump(pod_b_raw)

    p = tmp_path / "multi.yaml"
    p.write_text(pod_a + "\n---\n" + pod_b)

    out = await read_manifests(path=tmp_path)
    assert any(f.workload_name == "pod-b" and f.rule_id == "host-network" for f in out)


@pytest.mark.asyncio
async def test_init_containers_walked(tmp_path: Path) -> None:
    """initContainers also get the rule treatment."""
    pod = _pod(container=_safe_container())
    pod["spec"]["initContainers"] = [
        {
            "name": "init",
            "image": "busybox",
            "imagePullPolicy": "IfNotPresent",  # NOT Always — finding
            "securityContext": {"runAsUser": 1000, "readOnlyRootFilesystem": True},
            "resources": {"limits": {"cpu": "10m", "memory": "10Mi"}},
        }
    ]
    pod["spec"]["automountServiceAccountToken"] = False
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    init_findings = [f for f in out if f.container_name == "init"]
    assert any(f.rule_id == "image-pull-policy-not-always" for f in init_findings)


# ---------------------------- finding metadata ---------------------------


@pytest.mark.asyncio
async def test_finding_carries_manifest_path(tmp_path: Path) -> None:
    pod = _pod(container=_safe_container())
    pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
    p = _write_manifest(tmp_path, "evidence", pod)

    out = await read_manifests(path=tmp_path)
    findings = [f for f in out if f.rule_id == "privileged-container"]
    assert len(findings) == 1
    assert findings[0].manifest_path == str(p)


@pytest.mark.asyncio
async def test_default_namespace_when_unset(tmp_path: Path) -> None:
    pod = _pod(container=_safe_container())
    del pod["metadata"]["namespace"]
    pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
    _write_manifest(tmp_path, "p", pod)

    out = await read_manifests(path=tmp_path)
    findings = [f for f in out if f.rule_id == "privileged-container"]
    assert findings[0].namespace == "default"


@pytest.mark.asyncio
async def test_missing_workload_name_dropped(tmp_path: Path) -> None:
    pod = _pod(container=_safe_container())
    del pod["metadata"]["name"]
    pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(pod))

    # Add a good one too to confirm the agent doesn't bail.
    good = _pod(container=_safe_container())
    good["metadata"]["name"] = "good"
    good["spec"]["containers"][0]["securityContext"]["privileged"] = True
    _write_manifest(tmp_path, "good", good)

    out = await read_manifests(path=tmp_path)
    assert all(f.workload_name == "good" for f in out)
