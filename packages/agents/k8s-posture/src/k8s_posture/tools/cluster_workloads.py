"""`read_cluster_workloads` — live K8s cluster ingest via the kubernetes SDK.

D.6 v0.2. Replaces the file-based `read_manifests` for operators who want
to point at a kubeconfig and run, rather than pre-staging YAML snapshots.

**Pipeline contract is unchanged.** The reader emits the same
`ManifestFinding` shape as `read_manifests` (the file reader), so the
existing `normalize_manifest` lifts findings to OCSF 2003 with zero
change. Same 10-rule analyser; same severity table.

**How it works:**

1. Loads kubeconfig from the explicit path (Q4 — no in-cluster fallback in v0.2).
2. Walks 7 workload kinds via `CoreV1Api` / `AppsV1Api` / `BatchV1Api`:
   Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob.
3. Per kind: cluster-wide list when `namespace is None`, else namespace-scoped.
4. Each SDK object is serialised to its K8s-API-JSON dict shape (camelCase
   keys) via `client.ApiClient().sanitize_for_serialization`.
5. The dict is fed into the existing `_analyse_manifest` from
   `tools/manifests.py`. The returned findings have their `manifest_path`
   rewritten to a sentinel URL of the form `cluster:///{namespace}/{kind}/{name}`,
   so operators can distinguish file-sourced vs cluster-sourced findings
   at a glance in the evidence.

**RBAC / errors.** Lists that come back `403 Forbidden` raise
`ClusterReaderError` immediately — partial coverage is worse than a
clear failure (the operator-runbook says "fix RBAC, then rerun"). Other
non-2xx (e.g. `404` on a cluster that lacks `batch/v1 CronJob`) are
skipped per-kind so the run still completes against the kinds we can
read.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from k8s_posture.tools.manifests import ManifestFinding, _analyse_manifest


class ClusterReaderError(RuntimeError):
    """The live cluster could not be read (config, RBAC, or transport)."""


# (workload_kind, API class name, method name on that API).
_WORKLOAD_CALLS_ALL_NS: tuple[tuple[str, str, str], ...] = (
    ("Pod", "CoreV1Api", "list_pod_for_all_namespaces"),
    ("Deployment", "AppsV1Api", "list_deployment_for_all_namespaces"),
    ("StatefulSet", "AppsV1Api", "list_stateful_set_for_all_namespaces"),
    ("DaemonSet", "AppsV1Api", "list_daemon_set_for_all_namespaces"),
    ("ReplicaSet", "AppsV1Api", "list_replica_set_for_all_namespaces"),
    ("Job", "BatchV1Api", "list_job_for_all_namespaces"),
    ("CronJob", "BatchV1Api", "list_cron_job_for_all_namespaces"),
)

_WORKLOAD_CALLS_NS: tuple[tuple[str, str, str], ...] = (
    ("Pod", "CoreV1Api", "list_namespaced_pod"),
    ("Deployment", "AppsV1Api", "list_namespaced_deployment"),
    ("StatefulSet", "AppsV1Api", "list_namespaced_stateful_set"),
    ("DaemonSet", "AppsV1Api", "list_namespaced_daemon_set"),
    ("ReplicaSet", "AppsV1Api", "list_namespaced_replica_set"),
    ("Job", "BatchV1Api", "list_namespaced_job"),
    ("CronJob", "BatchV1Api", "list_namespaced_cron_job"),
)


async def read_cluster_workloads(
    *,
    kubeconfig: Path | str,
    namespace: str | None = None,
) -> tuple[ManifestFinding, ...]:
    """Read live K8s workloads and emit `ManifestFinding`s via the v0.1 10-rule analyser.

    Args:
        kubeconfig: Explicit path to a kubeconfig file. v0.2 has no
            in-cluster fallback (Q4) — operators must pass this.
        namespace: Optional namespace scope. `None` → cluster-wide list APIs;
            a string → namespace-scoped list APIs.

    Returns:
        Tuple of `ManifestFinding` records identical in shape to those
        emitted by `read_manifests` (the file reader). `normalize_manifest`
        lifts these to OCSF 2003 without modification.

    Raises:
        ClusterReaderError: kubeconfig missing or malformed; or RBAC denies
            the list permission on any required workload kind.
    """
    return await asyncio.to_thread(
        _read_sync,
        kubeconfig=Path(kubeconfig),
        namespace=namespace,
    )


def _read_sync(*, kubeconfig: Path, namespace: str | None) -> tuple[ManifestFinding, ...]:
    if not kubeconfig.exists():
        raise ClusterReaderError(f"kubeconfig not found: {kubeconfig}")
    try:
        config.load_kube_config(config_file=str(kubeconfig))
    except Exception as exc:
        raise ClusterReaderError(f"failed to load kubeconfig {kubeconfig}: {exc}") from exc

    serializer = client.ApiClient()
    detected_at = datetime.now(UTC)
    out: list[ManifestFinding] = []
    calls = _WORKLOAD_CALLS_ALL_NS if namespace is None else _WORKLOAD_CALLS_NS

    for kind, api_name, method_name in calls:
        api_klass = getattr(client, api_name)
        api = api_klass()
        try:
            if namespace is None:
                resp = getattr(api, method_name)()
            else:
                resp = getattr(api, method_name)(namespace=namespace)
        except ApiException as exc:
            if exc.status == 403:
                raise ClusterReaderError(
                    f"RBAC denied listing {kind} in {namespace or 'all namespaces'}: {exc.reason}"
                ) from exc
            # Other non-2xx (404 on missing CRD-shaped kinds, etc.) — skip.
            continue

        items = getattr(resp, "items", None) or []
        for item in items:
            manifest_dict = serializer.sanitize_for_serialization(item)
            if not isinstance(manifest_dict, dict):
                continue
            # `kind` is dropped on list-item serialisation; reinstate from the call context.
            manifest_dict.setdefault("kind", kind)

            metadata = manifest_dict.get("metadata") or {}
            ns = (
                str(metadata.get("namespace") or "default")
                if isinstance(metadata, dict)
                else "default"
            )
            name = (
                str(metadata.get("name") or "unknown") if isinstance(metadata, dict) else "unknown"
            )
            sentinel = f"cluster:///{ns}/{kind}/{name}"

            raw_findings = _analyse_manifest(
                manifest_dict,
                manifest_path=Path("placeholder"),  # rewritten below
                detected_at=detected_at,
            )
            for finding in raw_findings:
                out.append(finding.model_copy(update={"manifest_path": sentinel}))

    return tuple(out)


__all__ = [
    "ClusterReaderError",
    "read_cluster_workloads",
]
