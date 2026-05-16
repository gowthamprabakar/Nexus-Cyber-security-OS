"""Tests for `k8s_posture.tools.cluster_workloads.read_cluster_workloads`.

All tests mock the `kubernetes` SDK at the import site inside
`tools.cluster_workloads` (per Q5 of the v0.2 plan). No live cluster
needed; no envtest / kind dependency.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from k8s_posture.tools import cluster_workloads as mod
from k8s_posture.tools.cluster_workloads import (
    ClusterReaderError,
    read_cluster_workloads,
)
from kubernetes.client import (
    V1Container,
    V1CronJob,
    V1CronJobList,
    V1CronJobSpec,
    V1Deployment,
    V1DeploymentList,
    V1DeploymentSpec,
    V1Job,
    V1JobList,
    V1JobSpec,
    V1JobTemplateSpec,
    V1ObjectMeta,
    V1Pod,
    V1PodList,
    V1PodSpec,
    V1PodTemplateSpec,
    V1ResourceRequirements,
    V1SecurityContext,
)
from kubernetes.client.exceptions import ApiException

# ---------------------------- builders ------------------------------------


def _container(
    *,
    name: str = "nginx",
    run_as_user: int | None = 0,
    privileged: bool = False,
    image_pull_policy: str = "Always",
    has_limits: bool = True,
    read_only_root_fs: bool = True,
    allow_priv_esc: bool = False,
) -> V1Container:
    sec = V1SecurityContext(
        run_as_user=run_as_user,
        privileged=privileged,
        read_only_root_filesystem=read_only_root_fs,
        allow_privilege_escalation=allow_priv_esc,
    )
    resources = (
        V1ResourceRequirements(limits={"cpu": "500m", "memory": "256Mi"})
        if has_limits
        else V1ResourceRequirements()
    )
    return V1Container(
        name=name,
        image="nginx:latest",
        image_pull_policy=image_pull_policy,
        security_context=sec,
        resources=resources,
    )


def _clean_pod_spec() -> V1PodSpec:
    # All-clean pod spec — should produce ZERO manifest findings.
    return V1PodSpec(
        containers=[
            _container(
                run_as_user=1000,
                privileged=False,
                image_pull_policy="Always",
                has_limits=True,
                read_only_root_fs=True,
                allow_priv_esc=False,
            )
        ],
        host_network=False,
        host_pid=False,
        host_ipc=False,
        automount_service_account_token=False,
    )


def _pod(name: str = "frontend", namespace: str = "production") -> V1Pod:
    return V1Pod(
        api_version="v1",
        kind="Pod",
        metadata=V1ObjectMeta(name=name, namespace=namespace),
        spec=V1PodSpec(containers=[_container(run_as_user=0)]),  # run-as-root → HIGH finding
    )


def _deployment(name: str = "api", namespace: str = "production") -> V1Deployment:
    return V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=V1ObjectMeta(name=name, namespace=namespace),
        spec=V1DeploymentSpec(
            selector={"matchLabels": {"app": name}},
            template=V1PodTemplateSpec(
                metadata=V1ObjectMeta(labels={"app": name}),
                spec=V1PodSpec(containers=[_container(run_as_user=0, privileged=True)]),
            ),
        ),
    )


def _cronjob(name: str = "nightly", namespace: str = "batch") -> V1CronJob:
    return V1CronJob(
        api_version="batch/v1",
        kind="CronJob",
        metadata=V1ObjectMeta(name=name, namespace=namespace),
        spec=V1CronJobSpec(
            schedule="0 0 * * *",
            job_template=V1JobTemplateSpec(
                spec=V1JobSpec(
                    template=V1PodTemplateSpec(
                        spec=V1PodSpec(containers=[_container(run_as_user=0)]),
                    )
                )
            ),
        ),
    )


# ---------------------------- patcher -------------------------------------


def _install_fake_apis(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pods: list[V1Pod] | None = None,
    deployments: list[V1Deployment] | None = None,
    cronjobs: list[V1CronJob] | None = None,
    jobs: list[V1Job] | None = None,
    raise_403_for: set[str] | None = None,
    raise_404_for: set[str] | None = None,
    expected_namespace: str | None = None,
) -> dict[str, MagicMock]:
    """Patch the four API class factories the reader uses.

    Returns the dict of MagicMock instances so individual tests can assert
    which method was called and with what kwargs.
    """
    raise_403 = raise_403_for or set()
    raise_404 = raise_404_for or set()

    core = MagicMock()
    apps = MagicMock()
    batch = MagicMock()

    pod_list = V1PodList(items=pods or [])
    deploy_list = V1DeploymentList(items=deployments or [])
    cron_list = V1CronJobList(items=cronjobs or [])
    job_list = V1JobList(items=jobs or [])

    # Empty *List defaults so .items iteration never KeyErrors.
    from kubernetes.client import (
        V1DaemonSetList,
        V1ReplicaSetList,
        V1StatefulSetList,
    )

    empty_ss = V1StatefulSetList(items=[])
    empty_ds = V1DaemonSetList(items=[])
    empty_rs = V1ReplicaSetList(items=[])

    def _maybe_raise(kind: str) -> None:
        if kind in raise_403:
            raise ApiException(status=403, reason="Forbidden")
        if kind in raise_404:
            raise ApiException(status=404, reason="Not Found")

    def _wire(
        api: MagicMock,
        method_all: str,
        method_ns: str,
        ret_value: Any,
        kind: str,
    ) -> None:
        def _all_ns(**_: Any) -> Any:
            _maybe_raise(kind)
            return ret_value

        def _ns(namespace: str, **_: Any) -> Any:
            if expected_namespace is not None:
                assert namespace == expected_namespace, (
                    f"expected namespace={expected_namespace!r}, got {namespace!r}"
                )
            _maybe_raise(kind)
            return ret_value

        getattr(api, method_all).side_effect = _all_ns
        getattr(api, method_ns).side_effect = _ns

    _wire(core, "list_pod_for_all_namespaces", "list_namespaced_pod", pod_list, "Pod")
    _wire(
        apps,
        "list_deployment_for_all_namespaces",
        "list_namespaced_deployment",
        deploy_list,
        "Deployment",
    )
    _wire(
        apps,
        "list_stateful_set_for_all_namespaces",
        "list_namespaced_stateful_set",
        empty_ss,
        "StatefulSet",
    )
    _wire(
        apps,
        "list_daemon_set_for_all_namespaces",
        "list_namespaced_daemon_set",
        empty_ds,
        "DaemonSet",
    )
    _wire(
        apps,
        "list_replica_set_for_all_namespaces",
        "list_namespaced_replica_set",
        empty_rs,
        "ReplicaSet",
    )
    _wire(batch, "list_job_for_all_namespaces", "list_namespaced_job", job_list, "Job")
    _wire(
        batch,
        "list_cron_job_for_all_namespaces",
        "list_namespaced_cron_job",
        cron_list,
        "CronJob",
    )

    monkeypatch.setattr(mod.client, "CoreV1Api", lambda: core)
    monkeypatch.setattr(mod.client, "AppsV1Api", lambda: apps)
    monkeypatch.setattr(mod.client, "BatchV1Api", lambda: batch)
    # Defang the kubeconfig loader — tests use a real temp file but no real cluster.
    monkeypatch.setattr(mod.config, "load_kube_config", lambda **_: None)

    return {"core": core, "apps": apps, "batch": batch}


@pytest.fixture
def kubeconfig(tmp_path: Path) -> Path:
    cfg = tmp_path / "kubeconfig"
    cfg.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")
    return cfg


# ---------------------------- happy paths ---------------------------------


@pytest.mark.asyncio
async def test_empty_cluster_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    _install_fake_apis(monkeypatch)
    assert await read_cluster_workloads(kubeconfig=kubeconfig) == ()


@pytest.mark.asyncio
async def test_single_pod_with_run_as_root_emits_finding(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    _install_fake_apis(monkeypatch, pods=[_pod()])
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    assert any(f.rule_id == "run-as-root" for f in findings)


@pytest.mark.asyncio
async def test_deployment_with_privileged_and_root_emits_findings(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    _install_fake_apis(monkeypatch, deployments=[_deployment()])
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    rule_ids = {f.rule_id for f in findings}
    assert "run-as-root" in rule_ids
    assert "privileged-container" in rule_ids


@pytest.mark.asyncio
async def test_cronjob_nested_pod_spec_walks(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    """CronJob's pod spec is at spec.jobTemplate.spec.template.spec — the analyser
    must walk it (existing v0.1 behaviour, confirmed end-to-end through the live
    reader path)."""
    _install_fake_apis(monkeypatch, cronjobs=[_cronjob()])
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    assert any(f.rule_id == "run-as-root" and f.workload_kind == "CronJob" for f in findings)


# ---------------------------- workload-kind attribution ------------------


@pytest.mark.asyncio
async def test_findings_carry_correct_workload_kind(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    _install_fake_apis(
        monkeypatch,
        pods=[_pod(name="p1")],
        deployments=[_deployment(name="d1")],
    )
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    pod_findings = [f for f in findings if f.workload_kind == "Pod"]
    deploy_findings = [f for f in findings if f.workload_kind == "Deployment"]
    assert pod_findings, "expected Pod-kind findings"
    assert deploy_findings, "expected Deployment-kind findings"


@pytest.mark.asyncio
async def test_sentinel_manifest_path_set_on_findings(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    """The `manifest_path` evidence field carries `cluster:///<ns>/<kind>/<name>` so
    operators can distinguish file-sourced from cluster-sourced findings."""
    _install_fake_apis(monkeypatch, pods=[_pod(name="frontend", namespace="production")])
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    assert findings
    expected = "cluster:///production/Pod/frontend"
    assert all(f.manifest_path == expected for f in findings)


# ---------------------------- namespace scoping --------------------------


@pytest.mark.asyncio
async def test_namespace_scope_calls_namespaced_methods(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    apis = _install_fake_apis(
        monkeypatch,
        pods=[_pod(namespace="production")],
        expected_namespace="production",
    )
    await read_cluster_workloads(kubeconfig=kubeconfig, namespace="production")
    apis["core"].list_namespaced_pod.assert_called()
    apis["core"].list_pod_for_all_namespaces.assert_not_called()


@pytest.mark.asyncio
async def test_no_namespace_calls_cluster_wide_methods(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    apis = _install_fake_apis(monkeypatch, pods=[_pod()])
    await read_cluster_workloads(kubeconfig=kubeconfig)
    apis["core"].list_pod_for_all_namespaces.assert_called()
    apis["core"].list_namespaced_pod.assert_not_called()


# ---------------------------- error surfaces ------------------------------


@pytest.mark.asyncio
async def test_missing_kubeconfig_raises_cluster_reader_error(tmp_path: Path) -> None:
    with pytest.raises(ClusterReaderError, match="kubeconfig not found"):
        await read_cluster_workloads(kubeconfig=tmp_path / "does_not_exist.yaml")


@pytest.mark.asyncio
async def test_kubeconfig_load_failure_raises_cluster_reader_error(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    def _boom(**_: Any) -> None:
        raise RuntimeError("malformed kubeconfig")

    monkeypatch.setattr(mod.config, "load_kube_config", _boom)
    with pytest.raises(ClusterReaderError, match="failed to load kubeconfig"):
        await read_cluster_workloads(kubeconfig=kubeconfig)


@pytest.mark.asyncio
async def test_rbac_forbidden_raises_cluster_reader_error(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    _install_fake_apis(monkeypatch, raise_403_for={"Pod"})
    with pytest.raises(ClusterReaderError, match="RBAC denied listing Pod"):
        await read_cluster_workloads(kubeconfig=kubeconfig)


@pytest.mark.asyncio
async def test_404_on_kind_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    """An older cluster lacking `batch/v1 CronJob` returns 404 on that list. The
    reader must skip the kind and continue with the others."""
    _install_fake_apis(
        monkeypatch,
        pods=[_pod()],
        raise_404_for={"CronJob"},
    )
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    # We still got Pod findings — CronJob 404 didn't kill the run.
    assert findings
    assert all(f.workload_kind != "CronJob" for f in findings)


# ---------------------------- analyser-side coverage ---------------------


@pytest.mark.asyncio
async def test_clean_pod_emits_no_security_findings(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    clean_pod = V1Pod(
        api_version="v1",
        kind="Pod",
        metadata=V1ObjectMeta(name="clean", namespace="default"),
        spec=_clean_pod_spec(),
    )
    _install_fake_apis(monkeypatch, pods=[clean_pod])
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    assert findings == ()


@pytest.mark.asyncio
async def test_init_containers_walked(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    """An init container with run-as-root should fire the rule too — same as v0.1
    file-reader behaviour."""
    pod = V1Pod(
        api_version="v1",
        kind="Pod",
        metadata=V1ObjectMeta(name="frontend", namespace="production"),
        spec=V1PodSpec(
            containers=[_container(name="main", run_as_user=1000)],  # clean
            init_containers=[_container(name="initdb", run_as_user=0)],  # root → finding
        ),
    )
    _install_fake_apis(monkeypatch, pods=[pod])
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    assert any(f.rule_id == "run-as-root" and f.container_name == "initdb" for f in findings)


@pytest.mark.asyncio
async def test_default_namespace_when_metadata_omits_it(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    """Some K8s exports drop namespace on cluster-scoped lists — the analyser
    defaults to 'default'."""
    pod = V1Pod(
        api_version="v1",
        kind="Pod",
        metadata=V1ObjectMeta(name="anon"),  # no namespace
        spec=V1PodSpec(containers=[_container(run_as_user=0)]),
    )
    _install_fake_apis(monkeypatch, pods=[pod])
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    assert findings
    assert all(f.namespace == "default" for f in findings)


# ---------------------------- detected_at -------------------------------


@pytest.mark.asyncio
async def test_detected_at_is_timezone_aware_utc(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    from datetime import UTC

    _install_fake_apis(monkeypatch, pods=[_pod()])
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    assert findings
    assert findings[0].detected_at.tzinfo == UTC


# ---------------------------- ordering / determinism --------------------


@pytest.mark.asyncio
async def test_multiple_kinds_aggregate_in_call_order(
    monkeypatch: pytest.MonkeyPatch,
    kubeconfig: Path,
) -> None:
    """Walk-order is Pod → Deployment → StatefulSet → DaemonSet → ReplicaSet →
    Job → CronJob. Two kinds populated: findings must appear in that order so
    downstream dedup / summarisation stays deterministic."""
    _install_fake_apis(
        monkeypatch,
        pods=[_pod(name="p1")],
        deployments=[_deployment(name="d1")],
    )
    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    # First finding's workload should be the Pod (walked before Deployment).
    assert findings[0].workload_kind == "Pod"
    # At least one Deployment finding sits after the Pod ones.
    deploy_idxs = [i for i, f in enumerate(findings) if f.workload_kind == "Deployment"]
    pod_idxs = [i for i, f in enumerate(findings) if f.workload_kind == "Pod"]
    assert min(deploy_idxs) > max(pod_idxs)
