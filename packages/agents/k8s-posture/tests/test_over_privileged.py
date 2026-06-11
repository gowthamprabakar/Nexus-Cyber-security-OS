"""D.6 v0.2 Task 12 — over-privileged RBAC detection tests (Q4 heuristic)."""

from __future__ import annotations

from k8s_posture.rbac.enumerate import Role, RoleBinding, RoleRule, Subject
from k8s_posture.rbac.over_privileged import detect_over_privileged


def _wildcard_role() -> Role:
    return Role(
        "admin-like",
        "ClusterRole",
        "",
        rules=(RoleRule(api_groups=("*",), resources=("*",), verbs=("*",)),),
    )


def _ids(roles=(), bindings=()) -> set[str]:
    return {f.rule_id for f in detect_over_privileged(roles, bindings)}


def test_wildcard_role_flagged() -> None:
    [f] = [
        x
        for x in detect_over_privileged([_wildcard_role()], [])
        if x.rule_id == "wildcard-permissions"
    ]
    assert f.severity == "high" and f.name == "admin-like"


def test_secret_read_flagged() -> None:
    role = Role(
        "secret-reader", "Role", "ns", rules=(RoleRule(("",), ("secrets",), ("get", "list")),)
    )
    assert "broad-secret-access" in _ids(roles=[role])


def test_cluster_admin_binding_to_sa_critical() -> None:
    b = RoleBinding(
        "admin-binding",
        "ClusterRoleBinding",
        "",
        "ClusterRole",
        "cluster-admin",
        subjects=(Subject("ServiceAccount", "default", "prod"),),
    )
    [f] = detect_over_privileged([], [b])
    assert f.rule_id == "cluster-admin-binding" and f.severity == "critical"
    assert "default" in f.message


def test_cluster_admin_binding_to_user_not_flagged() -> None:
    # Only ServiceAccount subjects are flagged (the autonomous-workload concern).
    b = RoleBinding(
        "b",
        "ClusterRoleBinding",
        "",
        "ClusterRole",
        "cluster-admin",
        subjects=(Subject("User", "alice"),),
    )
    assert detect_over_privileged([], [b]) == ()


def test_narrow_role_not_flagged() -> None:
    role = Role("reader", "Role", "ns", rules=(RoleRule(("",), ("pods",), ("get",)),))
    assert detect_over_privileged([role], []) == ()


def test_non_cluster_admin_binding_not_flagged() -> None:
    b = RoleBinding(
        "b", "RoleBinding", "ns", "Role", "view", subjects=(Subject("ServiceAccount", "sa"),)
    )
    assert detect_over_privileged([], [b]) == ()


def test_empty() -> None:
    assert detect_over_privileged([], []) == ()
