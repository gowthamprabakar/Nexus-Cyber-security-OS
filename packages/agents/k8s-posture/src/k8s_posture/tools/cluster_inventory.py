"""Live cluster inventory discovery (v0.4 Stage 1.3/D.6).

Net-new kubernetes-client readers for the cluster *inventory* the catalogue (#711)
assigns K8s into the fleet graph — distinct from the v0.2 posture findings. Discovers:

- **Namespaces** (``CoreV1Api.list_namespace``).
- **Service accounts** (``list_service_account_for_all_namespaces``), capturing the
  ``eks.amazonaws.com/role-arn`` IRSA annotation — the bridge from a K8s workload
  identity to its assumed IAM role.
- **RBAC** roles + bindings (``RbacAuthorizationV1Api``), parsed by the existing
  :mod:`k8s_posture.rbac.enumerate` typed parsers (reused, not re-implemented).

Design seam for testability: the live cluster reads live behind a thin
:class:`ClusterReader` protocol whose implementations return already-serialized dicts.
:func:`inventory_from_reader` is the pure parse over those dicts — exercised with a
fake reader (canned cluster data) in tests; the live ``_LiveClusterReader`` (real
kubernetes client) is exercised only behind a ``NEXUS_LIVE_*`` integration gate. This
is the kube analogue of moto for AWS: real parsing logic, a stand-in for the cluster.

This module reads the cluster's own API objects (typed), NOT OCSF findings — no
findings-derived reverse-parse.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from k8s_posture.rbac.enumerate import Role, RoleBinding, enumerate_bindings, enumerate_roles
from k8s_posture.tools.cluster_workloads import ClusterReaderError

if TYPE_CHECKING:
    from collections.abc import Callable

#: The EKS IRSA annotation that maps a ServiceAccount to an assumed IAM role.
IRSA_ROLE_ANNOTATION = "eks.amazonaws.com/role-arn"


@dataclass(frozen=True, slots=True)
class K8sServiceAccount:
    """A namespaced ServiceAccount + its IRSA role-ARN annotation (if present)."""

    name: str
    namespace: str
    role_arn: str | None = None


@dataclass(frozen=True, slots=True)
class ClusterInventory:
    """Typed snapshot of a single cluster's identity + RBAC inventory."""

    cluster_id: str
    namespaces: tuple[str, ...] = field(default_factory=tuple)
    service_accounts: tuple[K8sServiceAccount, ...] = field(default_factory=tuple)
    roles: tuple[Role, ...] = field(default_factory=tuple)
    role_bindings: tuple[RoleBinding, ...] = field(default_factory=tuple)
    degraded: tuple[dict[str, str], ...] = field(default_factory=tuple)


class ClusterReader(Protocol):
    """Source of already-serialized cluster objects (dicts) — real client or fake."""

    def list_namespaces(self) -> list[dict[str, Any]]: ...
    def list_service_accounts(self) -> list[dict[str, Any]]: ...
    def list_roles(self) -> list[dict[str, Any]]: ...  # Role + ClusterRole (kind reinstated)
    def list_role_bindings(self) -> list[dict[str, Any]]: ...  # *Binding (kind reinstated)


def _name(obj: dict[str, Any]) -> str:
    meta = obj.get("metadata")
    return str(meta.get("name", "")) if isinstance(meta, dict) else ""


def _parse_service_account(obj: dict[str, Any]) -> K8sServiceAccount | None:
    meta = obj.get("metadata")
    if not isinstance(meta, dict) or not meta.get("name"):
        return None
    annotations = meta.get("annotations")
    role_arn = annotations.get(IRSA_ROLE_ANNOTATION) if isinstance(annotations, dict) else None
    return K8sServiceAccount(
        name=str(meta["name"]),
        namespace=str(meta.get("namespace", "")),
        role_arn=str(role_arn) if role_arn else None,
    )


def inventory_from_reader(reader: ClusterReader, *, cluster_id: str) -> ClusterInventory:
    """Pure: build a typed :class:`ClusterInventory` from a reader's serialized dicts."""
    namespaces = tuple(n for n in (_name(o) for o in reader.list_namespaces()) if n)
    service_accounts = tuple(
        sa for sa in (_parse_service_account(o) for o in reader.list_service_accounts()) if sa
    )
    return ClusterInventory(
        cluster_id=cluster_id,
        namespaces=namespaces,
        service_accounts=service_accounts,
        roles=enumerate_roles(reader.list_roles()),
        role_bindings=enumerate_bindings(reader.list_role_bindings()),
    )


class _LiveClusterReader:
    """Reads a live cluster via the kubernetes client, serializing items to dicts."""

    def __init__(self) -> None:
        from kubernetes import client

        self._core = client.CoreV1Api()
        self._rbac = client.RbacAuthorizationV1Api()
        self._serializer = client.ApiClient()

    def _items(self, call: Callable[[], Any], *, kind: str | None = None) -> list[dict[str, Any]]:
        from kubernetes.client.exceptions import ApiException

        try:
            resp = call()
        except ApiException as exc:
            if exc.status == 403:
                raise ClusterReaderError(
                    f"RBAC denied listing {kind or 'resource'}: {exc.reason}"
                ) from exc
            return []
        out: list[dict[str, Any]] = []
        for item in getattr(resp, "items", None) or []:
            data = self._serializer.sanitize_for_serialization(item)
            if isinstance(data, dict):
                if kind is not None:  # kind is dropped on list-item serialization; reinstate it.
                    data["kind"] = kind
                out.append(data)
        return out

    def list_namespaces(self) -> list[dict[str, Any]]:
        return self._items(self._core.list_namespace)

    def list_service_accounts(self) -> list[dict[str, Any]]:
        return self._items(self._core.list_service_account_for_all_namespaces)

    def list_roles(self) -> list[dict[str, Any]]:
        return [
            *self._items(self._rbac.list_role_for_all_namespaces, kind="Role"),
            *self._items(self._rbac.list_cluster_role, kind="ClusterRole"),
        ]

    def list_role_bindings(self) -> list[dict[str, Any]]:
        return [
            *self._items(self._rbac.list_role_binding_for_all_namespaces, kind="RoleBinding"),
            *self._items(self._rbac.list_cluster_role_binding, kind="ClusterRoleBinding"),
        ]


async def read_cluster_inventory(
    *,
    kubeconfig: Path | str | None = None,
    in_cluster: bool = False,
    cluster_id: str | None = None,
) -> ClusterInventory:
    """Read a live cluster's identity + RBAC inventory into a typed snapshot.

    Args:
        kubeconfig: Explicit kubeconfig path (mutually exclusive with ``in_cluster``).
        in_cluster: Load config from the Pod's mounted ServiceAccount token.
        cluster_id: Optional cluster identifier for graph node keys; defaults to the
            kubeconfig path or ``"in-cluster"``.

    Raises:
        ClusterReaderError: neither/both config sources set; kubeconfig missing or
            malformed; in-cluster config unavailable; or RBAC denies a required list.
    """
    return await asyncio.to_thread(
        _read_sync,
        kubeconfig=Path(kubeconfig) if kubeconfig is not None else None,
        in_cluster=in_cluster,
        cluster_id=cluster_id,
    )


def _read_sync(
    *, kubeconfig: Path | None, in_cluster: bool, cluster_id: str | None
) -> ClusterInventory:
    from kubernetes import config

    if kubeconfig is not None and in_cluster:
        raise ClusterReaderError(
            "kubeconfig and in_cluster are mutually exclusive — pick one source"
        )
    if kubeconfig is None and not in_cluster:
        raise ClusterReaderError(
            "no cluster config source — pass kubeconfig=... or in_cluster=True"
        )

    if in_cluster:
        try:
            config.load_incluster_config()
        except Exception as exc:
            raise ClusterReaderError(
                f"failed to load in-cluster config (not running in a cluster?): {exc}"
            ) from exc
        resolved_id = cluster_id or "in-cluster"
    elif kubeconfig is not None:
        if not kubeconfig.exists():
            raise ClusterReaderError(f"kubeconfig not found: {kubeconfig}")
        try:
            config.load_kube_config(config_file=str(kubeconfig))
        except Exception as exc:
            raise ClusterReaderError(f"failed to load kubeconfig {kubeconfig}: {exc}") from exc
        resolved_id = cluster_id or str(kubeconfig)
    else:  # unreachable: the guards above require exactly one config source
        raise ClusterReaderError(
            "no cluster config source — pass kubeconfig=... or in_cluster=True"
        )

    return inventory_from_reader(_LiveClusterReader(), cluster_id=resolved_id)


__all__ = [
    "IRSA_ROLE_ANNOTATION",
    "ClusterInventory",
    "ClusterReader",
    "K8sServiceAccount",
    "inventory_from_reader",
    "read_cluster_inventory",
]
