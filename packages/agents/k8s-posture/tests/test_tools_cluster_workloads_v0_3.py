"""Tests for D.6 v0.3 — `read_cluster_workloads` in-cluster ServiceAccount mode.

v0.2 tests live in `test_tools_cluster_workloads.py` and remain unchanged.
v0.3 adds the `in_cluster=True` branch — these tests cover:

- Happy path: `in_cluster=True` calls `config.load_incluster_config`.
- ConfigException → `ClusterReaderError` re-raise.
- Mutual exclusion (Q2): `kubeconfig` + `in_cluster` together → error.
- No-source: neither set → error.
- v0.3 smoke: `config.load_incluster_config` is importable.
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
    V1CronJobList,
    V1DaemonSetList,
    V1DeploymentList,
    V1JobList,
    V1ObjectMeta,
    V1Pod,
    V1PodList,
    V1PodSpec,
    V1ReplicaSetList,
    V1SecurityContext,
    V1StatefulSetList,
)


def _pod(name: str = "frontend", namespace: str = "production") -> V1Pod:
    return V1Pod(
        api_version="v1",
        kind="Pod",
        metadata=V1ObjectMeta(name=name, namespace=namespace),
        spec=V1PodSpec(
            containers=[
                V1Container(
                    name="nginx",
                    image="nginx:latest",
                    security_context=V1SecurityContext(run_as_user=0),
                )
            ]
        ),
    )


def _install_fake_apis_for_pod(monkeypatch: pytest.MonkeyPatch, pods: list[V1Pod]) -> None:
    """Minimal API patcher — returns the given pods and empty lists for everything else."""
    core = MagicMock()
    apps = MagicMock()
    batch = MagicMock()
    core.list_pod_for_all_namespaces.return_value = V1PodList(items=pods)
    apps.list_deployment_for_all_namespaces.return_value = V1DeploymentList(items=[])
    apps.list_stateful_set_for_all_namespaces.return_value = V1StatefulSetList(items=[])
    apps.list_daemon_set_for_all_namespaces.return_value = V1DaemonSetList(items=[])
    apps.list_replica_set_for_all_namespaces.return_value = V1ReplicaSetList(items=[])
    batch.list_job_for_all_namespaces.return_value = V1JobList(items=[])
    batch.list_cron_job_for_all_namespaces.return_value = V1CronJobList(items=[])
    monkeypatch.setattr(mod.client, "CoreV1Api", lambda: core)
    monkeypatch.setattr(mod.client, "AppsV1Api", lambda: apps)
    monkeypatch.setattr(mod.client, "BatchV1Api", lambda: batch)


# ---------------------------- v0.3 smoke ----------------------------------


def test_load_incluster_config_is_importable() -> None:
    """v0.3 depends on `config.load_incluster_config` being available on the kubernetes SDK."""
    from kubernetes import config

    assert hasattr(config, "load_incluster_config")


# ---------------------------- happy path ----------------------------------


@pytest.mark.asyncio
async def test_in_cluster_mode_invokes_load_incluster_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`in_cluster=True` triggers `config.load_incluster_config()` — NOT `load_kube_config`."""
    incluster_called = False
    kubeconfig_called = False

    def fake_incluster() -> None:
        nonlocal incluster_called
        incluster_called = True

    def fake_kubeconfig(**_: Any) -> None:
        nonlocal kubeconfig_called
        kubeconfig_called = True

    monkeypatch.setattr(mod.config, "load_incluster_config", fake_incluster)
    monkeypatch.setattr(mod.config, "load_kube_config", fake_kubeconfig)
    _install_fake_apis_for_pod(monkeypatch, [_pod()])

    findings = await read_cluster_workloads(in_cluster=True)

    assert incluster_called is True
    assert kubeconfig_called is False
    assert any(f.rule_id == "run-as-root" for f in findings)


@pytest.mark.asyncio
async def test_in_cluster_mode_returns_same_finding_shape_as_v0_2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The in-cluster path must produce findings indistinguishable in shape from kubeconfig mode —
    same OCSF source-type discriminator, same sentinel manifest_path scheme."""
    monkeypatch.setattr(mod.config, "load_incluster_config", lambda: None)
    _install_fake_apis_for_pod(monkeypatch, [_pod(name="api", namespace="payments")])

    findings = await read_cluster_workloads(in_cluster=True)
    assert findings
    f = findings[0]
    assert f.namespace == "payments"
    assert f.workload_name == "api"
    assert f.manifest_path == "cluster:///payments/Pod/api"


# ---------------------------- error: config load fails --------------------


@pytest.mark.asyncio
async def test_in_cluster_config_failure_raises_cluster_reader_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`config.load_incluster_config()` raises `ConfigException` when called outside a real
    cluster — the reader must catch it and re-raise as `ClusterReaderError` (Q3)."""

    def _boom() -> None:
        raise RuntimeError("Service host/port is not set")

    monkeypatch.setattr(mod.config, "load_incluster_config", _boom)

    with pytest.raises(ClusterReaderError, match="failed to load in-cluster config"):
        await read_cluster_workloads(in_cluster=True)


# ---------------------------- Q2 mutual exclusion -------------------------


@pytest.mark.asyncio
async def test_kubeconfig_and_in_cluster_together_raises(tmp_path: Path) -> None:
    """Q2 — supplying both config sources is a programmer error."""
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")

    with pytest.raises(ClusterReaderError, match="mutually exclusive"):
        await read_cluster_workloads(kubeconfig=kubeconfig, in_cluster=True)


@pytest.mark.asyncio
async def test_neither_kubeconfig_nor_in_cluster_raises() -> None:
    """No config source supplied → clear error rather than silent default."""
    with pytest.raises(ClusterReaderError, match="no cluster config source"):
        await read_cluster_workloads()


# ---------------------------- v0.2 path preserved -------------------------


@pytest.mark.asyncio
async def test_v0_2_kubeconfig_path_still_works(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The v0.2 kubeconfig-only path is unchanged. Defensive regression guard."""
    monkeypatch.setattr(mod.config, "load_kube_config", lambda **_: None)
    _install_fake_apis_for_pod(monkeypatch, [_pod()])
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")

    findings = await read_cluster_workloads(kubeconfig=kubeconfig)
    assert findings  # at least one run-as-root finding from the test pod


# ---------------------------- namespace scope works in in-cluster mode ----


@pytest.mark.asyncio
async def test_in_cluster_mode_supports_namespace_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Namespace scoping (Q3 of v0.2) works in v0.3's in-cluster mode too."""
    monkeypatch.setattr(mod.config, "load_incluster_config", lambda: None)

    core = MagicMock()
    apps = MagicMock()
    batch = MagicMock()
    pod_list = V1PodList(items=[_pod(namespace="production")])
    core.list_namespaced_pod.return_value = pod_list
    apps.list_namespaced_deployment.return_value = V1DeploymentList(items=[])
    apps.list_namespaced_stateful_set.return_value = V1StatefulSetList(items=[])
    apps.list_namespaced_daemon_set.return_value = V1DaemonSetList(items=[])
    apps.list_namespaced_replica_set.return_value = V1ReplicaSetList(items=[])
    batch.list_namespaced_job.return_value = V1JobList(items=[])
    batch.list_namespaced_cron_job.return_value = V1CronJobList(items=[])
    monkeypatch.setattr(mod.client, "CoreV1Api", lambda: core)
    monkeypatch.setattr(mod.client, "AppsV1Api", lambda: apps)
    monkeypatch.setattr(mod.client, "BatchV1Api", lambda: batch)

    findings = await read_cluster_workloads(in_cluster=True, namespace="production")

    core.list_namespaced_pod.assert_called_once()
    core.list_pod_for_all_namespaces.assert_not_called()
    assert findings
