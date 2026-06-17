"""Tests for the live cluster inventory parser (v0.4 Stage 1.3/D.6).

Exercises :func:`inventory_from_reader` — the pure parse over a cluster's serialized
objects — with a fake reader (canned cluster data). This is the kube analogue of moto:
real parsing logic + RBAC reuse (`enumerate_roles`/`enumerate_bindings`), a stand-in for
the cluster. The live ``_LiveClusterReader`` (real kubernetes client) is exercised only
behind a NEXUS_LIVE integration gate.
"""

from __future__ import annotations

from typing import Any

from k8s_posture.tools.cluster_inventory import (
    IRSA_ROLE_ANNOTATION,
    inventory_from_reader,
)


class _FakeClusterReader:
    """A ClusterReader returning canned serialized dicts (no live client)."""

    def __init__(
        self,
        *,
        namespaces: list[dict[str, Any]] | None = None,
        service_accounts: list[dict[str, Any]] | None = None,
        roles: list[dict[str, Any]] | None = None,
        role_bindings: list[dict[str, Any]] | None = None,
    ) -> None:
        self._ns = namespaces or []
        self._sa = service_accounts or []
        self._roles = roles or []
        self._bindings = role_bindings or []

    def list_namespaces(self) -> list[dict[str, Any]]:
        return self._ns

    def list_service_accounts(self) -> list[dict[str, Any]]:
        return self._sa

    def list_roles(self) -> list[dict[str, Any]]:
        return self._roles

    def list_role_bindings(self) -> list[dict[str, Any]]:
        return self._bindings


_ROLE_ARN = "arn:aws:iam::111122223333:role/app-role"


def _full_reader() -> _FakeClusterReader:
    return _FakeClusterReader(
        namespaces=[{"metadata": {"name": "default"}}, {"metadata": {"name": "kube-system"}}],
        service_accounts=[
            {
                "metadata": {
                    "name": "app-sa",
                    "namespace": "default",
                    "annotations": {IRSA_ROLE_ANNOTATION: _ROLE_ARN},
                }
            },
            {"metadata": {"name": "plain-sa", "namespace": "default"}},
        ],
        roles=[
            {
                "kind": "Role",
                "metadata": {"name": "reader", "namespace": "default"},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}],
            },
            {"kind": "ClusterRole", "metadata": {"name": "cluster-admin"}, "rules": []},
        ],
        role_bindings=[
            {
                "kind": "RoleBinding",
                "metadata": {"name": "rb", "namespace": "default"},
                "roleRef": {"kind": "Role", "name": "reader"},
                "subjects": [{"kind": "ServiceAccount", "name": "app-sa", "namespace": "default"}],
            }
        ],
    )


def test_inventory_parses_namespaces_sas_and_rbac() -> None:
    inv = inventory_from_reader(_full_reader(), cluster_id="test-cluster")

    assert inv.cluster_id == "test-cluster"
    assert inv.namespaces == ("default", "kube-system")

    by_name = {sa.name: sa for sa in inv.service_accounts}
    assert set(by_name) == {"app-sa", "plain-sa"}
    # IRSA annotation captured for the annotated SA; None for the plain one.
    assert by_name["app-sa"].role_arn == _ROLE_ARN
    assert by_name["app-sa"].namespace == "default"
    assert by_name["plain-sa"].role_arn is None

    # RBAC reuses the existing typed parsers.
    assert {r.name for r in inv.roles} == {"reader", "cluster-admin"}
    assert {r.kind for r in inv.roles} == {"Role", "ClusterRole"}
    assert len(inv.role_bindings) == 1
    assert inv.role_bindings[0].subjects[0].name == "app-sa"


def test_empty_cluster_yields_empty_inventory() -> None:
    inv = inventory_from_reader(_FakeClusterReader(), cluster_id="empty")
    assert inv.namespaces == ()
    assert inv.service_accounts == ()
    assert inv.roles == ()
    assert inv.role_bindings == ()


def test_nameless_objects_are_skipped() -> None:
    reader = _FakeClusterReader(
        namespaces=[{"metadata": {}}, {"metadata": {"name": "default"}}],
        service_accounts=[{"metadata": {}}, {"metadata": {"name": "sa1", "namespace": "default"}}],
    )
    inv = inventory_from_reader(reader, cluster_id="c")
    assert inv.namespaces == ("default",)
    assert [sa.name for sa in inv.service_accounts] == ["sa1"]
