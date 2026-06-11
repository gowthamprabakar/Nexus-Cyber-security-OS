"""RBAC resource enumeration (D.6 v0.2 Task 11).

Parses raw Kubernetes RBAC objects — ClusterRoles / Roles + ClusterRoleBindings /
RoleBindings — into typed structures for the basic over-privileged-role detection
(Task 12, Q4: enumeration + heuristic, not a full effective-permissions sim). Pure
parsing; no live calls.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class RoleRule:
    api_groups: tuple[str, ...] = field(default_factory=tuple)
    resources: tuple[str, ...] = field(default_factory=tuple)
    verbs: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Role:
    name: str
    kind: str  # "Role" | "ClusterRole"
    namespace: str
    rules: tuple[RoleRule, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Subject:
    kind: str  # "User" | "Group" | "ServiceAccount"
    name: str
    namespace: str = ""


@dataclass(frozen=True, slots=True)
class RoleBinding:
    name: str
    kind: str  # "RoleBinding" | "ClusterRoleBinding"
    namespace: str
    role_ref_kind: str
    role_ref_name: str
    subjects: tuple[Subject, ...] = field(default_factory=tuple)


def _strs(value: Any) -> tuple[str, ...]:
    return tuple(str(v) for v in value) if isinstance(value, list) else ()


def enumerate_roles(raw_roles: Sequence[dict[str, Any]]) -> tuple[Role, ...]:
    """Parse ClusterRole / Role objects → typed `Role`s. No-name objects skipped."""
    out: list[Role] = []
    for obj in raw_roles:
        meta_raw = obj.get("metadata")
        meta: dict[str, Any] = meta_raw if isinstance(meta_raw, dict) else {}
        name = str(meta.get("name", ""))
        if not name:
            continue
        rules: list[RoleRule] = []
        for rule in obj.get("rules", []) if isinstance(obj.get("rules"), list) else []:
            if isinstance(rule, dict):
                rules.append(
                    RoleRule(
                        api_groups=_strs(rule.get("apiGroups")),
                        resources=_strs(rule.get("resources")),
                        verbs=_strs(rule.get("verbs")),
                    )
                )
        out.append(
            Role(
                name=name,
                kind=str(obj.get("kind", "Role")),
                namespace=str(meta.get("namespace", "")),
                rules=tuple(rules),
            )
        )
    return tuple(out)


def enumerate_bindings(raw_bindings: Sequence[dict[str, Any]]) -> tuple[RoleBinding, ...]:
    """Parse ClusterRoleBinding / RoleBinding objects → typed `RoleBinding`s."""
    out: list[RoleBinding] = []
    for obj in raw_bindings:
        meta_raw = obj.get("metadata")
        meta: dict[str, Any] = meta_raw if isinstance(meta_raw, dict) else {}
        name = str(meta.get("name", ""))
        if not name:
            continue
        role_ref_raw = obj.get("roleRef")
        role_ref: dict[str, Any] = role_ref_raw if isinstance(role_ref_raw, dict) else {}
        subjects: list[Subject] = []
        for s in obj.get("subjects", []) if isinstance(obj.get("subjects"), list) else []:
            if isinstance(s, dict):
                subjects.append(
                    Subject(
                        kind=str(s.get("kind", "")),
                        name=str(s.get("name", "")),
                        namespace=str(s.get("namespace", "")),
                    )
                )
        out.append(
            RoleBinding(
                name=name,
                kind=str(obj.get("kind", "RoleBinding")),
                namespace=str(meta.get("namespace", "")),
                role_ref_kind=str(role_ref.get("kind", "")),
                role_ref_name=str(role_ref.get("name", "")),
                subjects=tuple(subjects),
            )
        )
    return tuple(out)
