"""D.6 v0.2 Task 11 — RBAC resource enumeration tests."""

from __future__ import annotations

from k8s_posture.rbac.enumerate import (
    Role,
    RoleBinding,
    enumerate_bindings,
    enumerate_roles,
)

_CLUSTER_ROLE = {
    "kind": "ClusterRole",
    "metadata": {"name": "admin-like"},
    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
}

_BINDING = {
    "kind": "ClusterRoleBinding",
    "metadata": {"name": "admin-binding"},
    "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
    "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "prod"}],
}


def test_enumerate_role() -> None:
    [role] = enumerate_roles([_CLUSTER_ROLE])
    assert isinstance(role, Role)
    assert role.name == "admin-like" and role.kind == "ClusterRole"
    [rule] = role.rules
    assert rule.api_groups == ("*",) and rule.resources == ("*",) and rule.verbs == ("*",)


def test_role_without_name_skipped() -> None:
    assert enumerate_roles([{"rules": []}]) == ()


def test_role_with_no_rules() -> None:
    [role] = enumerate_roles([{"kind": "Role", "metadata": {"name": "empty", "namespace": "ns"}}])
    assert role.rules == () and role.namespace == "ns"


def test_enumerate_binding() -> None:
    [binding] = enumerate_bindings([_BINDING])
    assert isinstance(binding, RoleBinding)
    assert binding.name == "admin-binding" and binding.role_ref_name == "cluster-admin"
    [subject] = binding.subjects
    assert subject.kind == "ServiceAccount" and subject.name == "default"


def test_binding_without_name_skipped() -> None:
    assert enumerate_bindings([{"roleRef": {}}]) == ()


def test_binding_with_no_subjects() -> None:
    [b] = enumerate_bindings(
        [{"kind": "RoleBinding", "metadata": {"name": "b"}, "roleRef": {"name": "r"}}]
    )
    assert b.subjects == () and b.role_ref_name == "r"


def test_empty_inputs() -> None:
    assert enumerate_roles([]) == () and enumerate_bindings([]) == ()
