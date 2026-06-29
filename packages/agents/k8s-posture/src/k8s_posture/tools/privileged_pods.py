"""Privileged-pod + image reader (path-6 K8s attack path).

Lists pods, flags those running a privileged container, and pairs each with its container
image ref — the ``RUNS_IMAGE`` bridge key vulnerability scans CVEs onto. A privileged pod can
escape to the node, so a privileged pod running a *vulnerable* image is a real attack path:
exploit the CVE for RCE in the container, then escape to the host.

Pure parser over ``kubectl get pods -A -o json`` + a thin subprocess wrapper, so the parse is
unit-tested without a cluster and the live read runs against any kube context (kind/EKS/AKS/GKE).
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from shutil import which
from typing import Any


@dataclass(frozen=True, slots=True)
class PrivilegedWorkload:
    namespace: str
    name: str
    image_ref: str


def privileged_workloads(pods_json: dict[str, Any]) -> list[PrivilegedWorkload]:
    """Pods with a privileged container, paired with that container's image ref.

    ``pods_json`` is the parsed ``kubectl get pods -o json`` document. ``privileged`` is a
    container-level ``securityContext`` flag in Kubernetes, so containers are checked (not the
    pod-level securityContext)."""
    out: list[PrivilegedWorkload] = []
    for item in pods_json.get("items") or []:
        meta = item.get("metadata") or {}
        containers = (item.get("spec") or {}).get("containers") or []
        privileged = next(
            (c for c in containers if (c.get("securityContext") or {}).get("privileged") is True),
            None,
        )
        if privileged is None or not privileged.get("image"):
            continue
        out.append(
            PrivilegedWorkload(
                namespace=str(meta.get("namespace") or "default"),
                name=str(meta.get("name") or "unknown"),
                image_ref=str(privileged["image"]),
            )
        )
    return out


def kubectl_available() -> bool:
    return which("kubectl") is not None


def read_privileged_workloads(
    *, context: str | None = None, timeout: float = 30.0
) -> list[PrivilegedWorkload]:
    """Live read: ``kubectl get pods -A -o json`` against ``context``, parsed."""
    args = ["kubectl"]
    if context:
        args += ["--context", context]
    args += ["get", "pods", "-A", "-o", "json"]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True)  # noqa: S603
    return privileged_workloads(json.loads(proc.stdout))


__all__ = [
    "PrivilegedWorkload",
    "kubectl_available",
    "privileged_workloads",
    "read_privileged_workloads",
]
