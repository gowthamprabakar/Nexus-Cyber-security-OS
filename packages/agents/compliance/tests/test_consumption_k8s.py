"""compliance v0.2 Task 11 — k8s-posture OCSF 2003 consumption (CIS-K8s)."""

from __future__ import annotations

import asyncio

from compliance.consumption import evaluate_framework, source_evaluation
from compliance.tools.cis_k8s_benchmark import read_cis_k8s_benchmark

_AGENT = "k8s_posture"


def _k8s_report(*rule_ids: str) -> dict:
    # k8s-posture reuses F.3's build_finding, so compliance.control holds the rule id
    # (kube-bench control id like "1.2.1", or a runtime/RBAC rule like "privileged-container").
    return {
        "agent": "k8s_posture",
        "findings": [
            {"class_uid": 2003, "compliance": {"control": rid, "status": "Failed"}}
            for rid in rule_ids
        ],
    }


def test_kube_bench_failing_control() -> None:
    controls = asyncio.run(read_cis_k8s_benchmark())
    _, failing = source_evaluation(_k8s_report("1.2.1"), controls, source_agent=_AGENT)
    assert "1.2.1" in failing


def test_multi_source_runtime_fails_the_control() -> None:
    # CIS-K8s 5.2.2 maps to kube-bench "5.2.2" + runtime "privileged-container".
    # A runtime finding alone fails the control (multi-emitter aggregation).
    controls = asyncio.run(read_cis_k8s_benchmark())
    rollup = evaluate_framework(
        "cis_k8s_v18", _k8s_report("privileged-container"), controls, source_agent=_AGENT
    )
    # 5.2.2 fails via its runtime mapping.
    assert rollup.fail_count >= 1


def test_rbac_cross_map() -> None:
    controls = asyncio.run(read_cis_k8s_benchmark())
    _, failing = source_evaluation(
        _k8s_report("cluster-admin-binding"), controls, source_agent=_AGENT
    )
    assert "cluster-admin-binding" in failing  # 5.1.1 RBAC mapping


def test_all_pass_when_no_findings() -> None:
    controls = asyncio.run(read_cis_k8s_benchmark())
    rollup = evaluate_framework("cis_k8s_v18", _k8s_report(), controls, source_agent=_AGENT)
    # All 15 controls have k8s_posture mappings + the agent ran with no failures -> all PASS.
    assert rollup.fail_count == 0 and rollup.pass_count == 15
    assert rollup.coverage_pct == 100.0


def test_no_report_zero_coverage() -> None:
    controls = asyncio.run(read_cis_k8s_benchmark())
    rollup = evaluate_framework("cis_k8s_v18", {}, controls, source_agent=_AGENT)
    assert rollup.pass_count == 0 and rollup.coverage_pct == 0.0
