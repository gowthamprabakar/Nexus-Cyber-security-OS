"""remediation v0.2 Task 11 — k8s-posture source mapping (Q3/WI-A1)."""

from __future__ import annotations

from remediation.action_classes import ACTION_CLASS_REGISTRY
from remediation.tools.source_mapping import (
    K8S_POSTURE_ACTIONABLE_RULES,
    actionable_rule_ids_for,
    is_actionable,
)


def test_k8s_posture_maps_all_seven_action_rules() -> None:
    # k8s-posture is the primary source; its actionable rules are exactly the 7 action keys.
    assert frozenset(ACTION_CLASS_REGISTRY) == K8S_POSTURE_ACTIONABLE_RULES
    assert len(K8S_POSTURE_ACTIONABLE_RULES) == 7


def test_actionable_for_known_rule() -> None:
    assert is_actionable("k8s_posture", "run-as-root")
    assert is_actionable("k8s_posture", "privileged-container")


def test_non_actionable_rule() -> None:
    # host-network is detected but not remediated at v0.2 (v0.3).
    assert not is_actionable("k8s_posture", "host-network")


def test_unknown_source_empty() -> None:
    assert actionable_rule_ids_for("nope") == frozenset()
    assert not is_actionable("nope", "run-as-root")
