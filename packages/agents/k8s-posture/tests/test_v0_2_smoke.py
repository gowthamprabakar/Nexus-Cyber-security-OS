"""Smoke tests for D.6 v0.2 — live cluster API ingest.

Asserts the `kubernetes` SDK is installed and the surfaces v0.2 will consume
(`config`, `client.CoreV1Api`, `client.AppsV1Api`, `client.BatchV1Api`,
`ApiException`) are importable. Task 1 ships ONLY the dependency wiring; the
live `read_cluster_workloads` tool lands in Task 2.
"""

from __future__ import annotations


def test_kubernetes_sdk_installed() -> None:
    """v0.2 depends on the `kubernetes` Python SDK (Q2 — sync SDK + asyncio.to_thread)."""
    import kubernetes

    assert hasattr(kubernetes, "__version__")
    # 31.x is the floor; newer is fine.
    major = int(kubernetes.__version__.split(".")[0])
    assert major >= 31, f"kubernetes SDK >=31.0.0 required; got {kubernetes.__version__}"


def test_kubernetes_config_loader_available() -> None:
    """`config.load_kube_config(config_file=...)` is what the reader will call."""
    from kubernetes import config

    assert hasattr(config, "load_kube_config")


def test_kubernetes_api_surfaces_available() -> None:
    """The three API groups the workload reader will use."""
    from kubernetes import client

    assert hasattr(client, "CoreV1Api")  # Pods
    assert hasattr(client, "AppsV1Api")  # Deployments / StatefulSets / DaemonSets / ReplicaSets
    assert hasattr(client, "BatchV1Api")  # Jobs / CronJobs


def test_kubernetes_api_exception_class_available() -> None:
    """`ApiException` is the error class the reader will catch for RBAC/403 surfaces."""
    from kubernetes.client.exceptions import ApiException

    assert issubclass(ApiException, Exception)


def test_v0_2_reader_module_present() -> None:
    """The live cluster reader module ships in Task 2.

    The Task 1 anti-marker has flipped to existence-asserting.
    """
    from k8s_posture.tools.cluster_workloads import (  # noqa: F401
        ClusterReaderError,
        read_cluster_workloads,
    )
