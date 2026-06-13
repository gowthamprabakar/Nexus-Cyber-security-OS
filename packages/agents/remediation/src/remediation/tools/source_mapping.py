"""Source-agent → actionable-rule mapping (remediation v0.2 Task 11-12, Q3/WI-A1).

A.1 only remediates findings whose ``rule_id`` maps to one of its action classes. Q3 scopes the
source agents to the **K8s-relevant** ones: **k8s-posture** (the primary source — CIS K8s /
Polaris / kube-bench workload findings) plus the cloud-K8s management findings from **F.3** (EKS)
and **D.5** (AKS/GKE), added in Task 12. This module is the pure, per-source registry (WI-A1 —
coverage tracked per source, never an aggregate); the reader stays source-agnostic and tenant
scoping is enforced by ``invariants.assert_tenant_scoped`` (Task 18, WI-A18).
"""

from __future__ import annotations

from remediation.action_classes import ACTION_CLASS_REGISTRY

#: k8s-posture (D.6) is the primary source — its workload rule_ids are exactly A.1's action keys.
K8S_POSTURE_ACTIONABLE_RULES: frozenset[str] = frozenset(ACTION_CLASS_REGISTRY)

#: Per-source actionable-rule registry (Q3). Task 12 adds the F.3 + D.5 cloud-K8s entries.
SOURCE_RULE_MAP: dict[str, frozenset[str]] = {
    "k8s_posture": K8S_POSTURE_ACTIONABLE_RULES,
}


def actionable_rule_ids_for(source_agent: str) -> frozenset[str]:
    """The rule_ids from ``source_agent`` that A.1 can remediate (empty for unknown sources)."""
    return SOURCE_RULE_MAP.get(source_agent, frozenset())


def is_actionable(source_agent: str, rule_id: str) -> bool:
    """True iff ``source_agent`` emits ``rule_id`` and A.1 has an action class for it."""
    return rule_id in actionable_rule_ids_for(source_agent)
