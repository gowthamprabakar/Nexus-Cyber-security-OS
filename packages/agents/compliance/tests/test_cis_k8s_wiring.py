"""compliance v0.2 Task 5 — CIS-K8s reader + real-rule wiring guard (WI-C2)."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import yaml
from compliance.tools.cis_k8s_benchmark import (
    default_cis_k8s_v18_path,
    read_cis_k8s_benchmark,
)

# k8s-posture's fixed runtime + RBAC rule ids (ground-truthed from Cycle 8 —
# runtime/posture_rules.py + rbac/over_privileged.py). kube-bench findings carry
# rule_id == the CIS control id, handled separately below.
_K8S_RUNTIME_RBAC_RULES = {
    "privileged-container",
    "run-as-root",
    "missing-run-as-user",
    "host-network",
    "host-pid",
    "dangerous-capabilities",
    "privilege-escalation",
    "writable-root-fs",
    "wildcard-permissions",
    "broad-secret-access",
    "cluster-admin-binding",
}
_CONTROL_ID_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")

_LIB = default_cis_k8s_v18_path()


def _controls() -> list[dict]:
    data = yaml.safe_load(Path(_LIB).read_text(encoding="utf-8"))
    return [c for c in data["controls"] if isinstance(c, dict)]


def _mappings(control: dict) -> list[dict]:
    return [m for m in (control.get("source_mappings") or []) if isinstance(m, dict)]


def test_default_path_exists() -> None:
    assert Path(_LIB).is_file() and _LIB.name == "cis_k8s_v18.yaml"


def test_reader_loads_controls() -> None:
    controls = asyncio.run(read_cis_k8s_benchmark())
    assert len(controls) == 15  # the CIS_K8S_V18 catalog
    assert any(c.control_id == "5.2.2" for c in controls)


def test_every_mapping_is_a_real_k8s_posture_rule() -> None:
    """No fabricated coverage: a kube-bench mapping's rule_id is a CIS control id, or it is
    one of k8s-posture's fixed runtime/RBAC rule ids."""
    for control in _controls():
        for m in _mappings(control):
            assert m.get("source_agent") == "k8s_posture"
            rid = m["source_rule_id"]
            assert _CONTROL_ID_RE.match(rid) or rid in _K8S_RUNTIME_RBAC_RULES, (
                f"control {control['control_id']} maps to unknown rule {rid!r}"
            )


def test_kube_bench_self_mapping() -> None:
    # Each control maps to its own kube-bench rule_id (rule_id == control_id).
    for control in _controls():
        rules = {m["source_rule_id"] for m in _mappings(control)}
        assert control["control_id"] in rules


def test_multi_source_cross_maps() -> None:
    by_id = {c["control_id"]: {m["source_rule_id"] for m in _mappings(c)} for c in _controls()}
    assert "privileged-container" in by_id["5.2.2"]  # kube-bench + runtime
    assert "run-as-root" in by_id["5.2.6"]
    assert "cluster-admin-binding" in by_id["5.1.1"]  # kube-bench + RBAC
