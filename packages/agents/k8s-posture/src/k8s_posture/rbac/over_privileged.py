"""Over-privileged RBAC detection (D.6 v0.2 Task 12).

Per **Q4** a **basic heuristic** over the enumerated roles + bindings (Task 11) — NOT a
full effective-permissions simulator (that resolves cluster-roles x role-bindings and is
v0.3). Flags the high-signal cases: wildcard `*.*.*` roles, broad secret access, and
cluster-admin bound to a ServiceAccount. Pure + deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from k8s_posture.rbac.enumerate import Role, RoleBinding, RoleRule

_WILDCARD = "*"
_SECRET_READ_VERBS = frozenset({"*", "get", "list", "watch"})


@dataclass(frozen=True, slots=True)
class RbacFinding:
    rule_id: str
    severity: str
    kind: str
    name: str
    namespace: str
    message: str


def _is_wildcard_rule(rule: RoleRule) -> bool:
    return _WILDCARD in rule.verbs and _WILDCARD in rule.resources and _WILDCARD in rule.api_groups


def _reads_secrets(rule: RoleRule) -> bool:
    return ("secrets" in rule.resources or _WILDCARD in rule.resources) and bool(
        set(rule.verbs) & _SECRET_READ_VERBS
    )


def detect_over_privileged(
    roles: Sequence[Role], bindings: Sequence[RoleBinding]
) -> tuple[RbacFinding, ...]:
    """Detect over-privileged roles + bindings via basic heuristics (Q4)."""
    out: list[RbacFinding] = []
    for role in roles:
        if any(_is_wildcard_rule(r) for r in role.rules):
            out.append(
                RbacFinding(
                    "wildcard-permissions",
                    "high",
                    role.kind,
                    role.name,
                    role.namespace,
                    "role grants all verbs on all resources (*.*.*)",
                )
            )
        if any(_reads_secrets(r) for r in role.rules):
            out.append(
                RbacFinding(
                    "broad-secret-access",
                    "high",
                    role.kind,
                    role.name,
                    role.namespace,
                    "role can read Secrets",
                )
            )
    for binding in bindings:
        if binding.role_ref_name != "cluster-admin":
            continue
        for subject in binding.subjects:
            if subject.kind == "ServiceAccount":
                out.append(
                    RbacFinding(
                        "cluster-admin-binding",
                        "critical",
                        binding.kind,
                        binding.name,
                        binding.namespace,
                        f"cluster-admin bound to ServiceAccount {subject.name}",
                    )
                )
    return tuple(out)
