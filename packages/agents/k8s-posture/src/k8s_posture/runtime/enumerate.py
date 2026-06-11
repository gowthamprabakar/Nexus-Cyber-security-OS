"""Runtime state enumeration (D.6 v0.2 Task 9).

Turns the kubelet `/pods` payload (Task 8) into typed **runtime** state — pods, their
containers, and the security-relevant fields (privileged, runAsUser, added capabilities,
hostNetwork/hostPID, read-only root FS) — that the runtime posture rules (Task 10) and
the RBAC analysis consume. Pure parsing; no live calls.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ContainerState:
    name: str
    image: str = ""
    privileged: bool = False
    run_as_user: int | None = None
    added_capabilities: tuple[str, ...] = field(default_factory=tuple)
    read_only_root_fs: bool = False
    allow_privilege_escalation: bool = True


@dataclass(frozen=True, slots=True)
class PodState:
    name: str
    namespace: str
    host_network: bool = False
    host_pid: bool = False
    service_account: str = ""
    containers: tuple[ContainerState, ...] = field(default_factory=tuple)


def _container(raw: dict[str, Any]) -> ContainerState:
    sc_raw = raw.get("securityContext")
    sc: dict[str, Any] = sc_raw if isinstance(sc_raw, dict) else {}
    caps_raw = sc.get("capabilities")
    caps: dict[str, Any] = caps_raw if isinstance(caps_raw, dict) else {}
    run_as_user = sc.get("runAsUser")
    ape = sc.get("allowPrivilegeEscalation")
    return ContainerState(
        name=str(raw.get("name", "")),
        image=str(raw.get("image", "")),
        privileged=bool(sc.get("privileged")),
        run_as_user=run_as_user if isinstance(run_as_user, int) else None,
        added_capabilities=tuple(str(c) for c in (caps.get("add") or [])),
        read_only_root_fs=bool(sc.get("readOnlyRootFilesystem")),
        allow_privilege_escalation=True if ape is None else bool(ape),
    )


def enumerate_pods(pods: Sequence[dict[str, Any]]) -> tuple[PodState, ...]:
    """Parse kubelet pod objects → typed `PodState`s. Pods without a name are skipped."""
    out: list[PodState] = []
    for pod in pods:
        meta_raw = pod.get("metadata")
        meta: dict[str, Any] = meta_raw if isinstance(meta_raw, dict) else {}
        spec_raw = pod.get("spec")
        spec: dict[str, Any] = spec_raw if isinstance(spec_raw, dict) else {}
        name = str(meta.get("name", ""))
        if not name:
            continue
        containers = tuple(_container(c) for c in spec.get("containers", []) if isinstance(c, dict))
        out.append(
            PodState(
                name=name,
                namespace=str(meta.get("namespace", "default")) or "default",
                host_network=bool(spec.get("hostNetwork")),
                host_pid=bool(spec.get("hostPID")),
                service_account=str(spec.get("serviceAccountName", "")),
                containers=containers,
            )
        )
    return tuple(out)
