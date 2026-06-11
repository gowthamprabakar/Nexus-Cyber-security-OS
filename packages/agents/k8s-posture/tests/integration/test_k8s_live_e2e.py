"""WI-K4 (HARD) — live K8s-posture end-to-end (D.6 v0.2 Task 18).

Two-layer per the WI-V6 / WI-I4 / WI-T4 / WI-R4 / WI-N4 lineage:

1. **Offline layer (every push):** the real live scan pipeline — kube-bench + Polaris +
   kubelet runtime + RBAC → OCSF 2003 — exercised end-to-end with injected fakes (no live
   cluster). Per-cluster isolation (Q3/WI-K8) + cloud-agnostic auth (Q2) are exercised.
2. **Gated-live layer (`NEXUS_LIVE_K8S_POSTURE=1`):** probes a live cluster; skipped in CI.

Honest scope (WI-K3): the live scanners are e2e-tested through **emission**; wiring them
into the agent's `run()` loop is a v0.3 carry-forward — the offline `run()` stays the
deterministic OCSF-emitting path (WI-K5 byte-identical).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from k8s_posture.cluster_auth import ClusterProvider, resolve_cluster
from k8s_posture.isolation import ClusterScanSession, assert_single_cluster_context
from k8s_posture.live_lane import k8s_reachable
from k8s_posture.normalizers.kube_bench_live import normalize_live_kube_bench
from k8s_posture.normalizers.polaris_live import normalize_live_polaris
from k8s_posture.rbac.emission import emit_rbac_findings, emit_runtime_findings
from k8s_posture.rbac.enumerate import enumerate_bindings, enumerate_roles
from k8s_posture.rbac.over_privileged import detect_over_privileged
from k8s_posture.runtime.enumerate import enumerate_pods
from k8s_posture.runtime.posture_rules import evaluate_runtime_posture
from k8s_posture.schemas import CloudPostureFinding
from k8s_posture.tools.kube_bench_live import KubeBenchLiveScanner
from k8s_posture.tools.kubelet_client import KubeletClient
from k8s_posture.tools.polaris_live import PolarisLiveScanner
from shared.fabric.envelope import NexusEnvelope

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)

_KUBE_BENCH = {
    "Controls": [
        {
            "node_type": "master",
            "tests": [
                {
                    "section": "1.2",
                    "desc": "API Server",
                    "results": [
                        {"test_number": "1.2.1", "test_desc": "anonymous-auth", "status": "FAIL"}
                    ],
                }
            ],
        }
    ]
}
_POLARIS = {
    "Results": [
        {
            "Name": "web",
            "Namespace": "prod",
            "Kind": "Deployment",
            "PodResult": {
                "ContainerResults": [
                    {
                        "Name": "app",
                        "Results": {
                            "x": {
                                "ID": "x",
                                "Success": False,
                                "Severity": "danger",
                                "Message": "m",
                                "Category": "Security",
                            }
                        },
                    }
                ]
            },
        }
    ]
}
_PODS = {
    "items": [
        {
            "metadata": {"name": "web", "namespace": "prod"},
            "spec": {
                "hostNetwork": True,
                "containers": [{"name": "app", "securityContext": {"privileged": True}}],
            },
        }
    ]
}
_ROLE = {
    "kind": "ClusterRole",
    "metadata": {"name": "admin-like"},
    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
}
_KUBECONFIG = {
    "current-context": "prod",
    "contexts": [{"name": "prod", "context": {"cluster": "arn:aws:eks:us-east-1:1:cluster/prod"}}],
    "clusters": [
        {
            "name": "arn:aws:eks:us-east-1:1:cluster/prod",
            "cluster": {"server": "https://x.eks.amazonaws.com"},
        }
    ],
}


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_d6",
        tenant_id="cust_test",
        agent_id="k8s_posture@0.2.0",
        nlah_version="0.2.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


class _KubeRunner:
    def __init__(self, blob: dict[str, Any]) -> None:
        self._blob = blob

    def run(self, *, kubeconfig: str, context: str | None = None) -> dict[str, Any]:
        return self._blob


class _Transport:
    def get(self, path: str) -> dict[str, Any]:
        return _PODS if path == "/pods" else {}


def _all_2003(findings: tuple[CloudPostureFinding, ...]) -> bool:
    return all(f.to_dict()["class_uid"] == 2003 for f in findings)


# ------------------- offline layer: full pipeline ------------------------


def test_cluster_auth_resolves_provider() -> None:
    resolved = resolve_cluster(_KUBECONFIG)
    assert resolved.provider == ClusterProvider.EKS  # cloud-agnostic via kubeconfig (Q2)


def test_kube_bench_pipeline_emits_2003() -> None:
    kbf = KubeBenchLiveScanner(_KubeRunner(_KUBE_BENCH)).scan(
        kubeconfig="c", context="prod", detected_at=_T
    )
    findings = normalize_live_kube_bench(kbf, envelope=_envelope(), scan_time=_T)
    assert findings and _all_2003(findings)


def test_polaris_pipeline_emits_2003() -> None:
    pf = PolarisLiveScanner(_KubeRunner(_POLARIS)).scan(
        kubeconfig="c", context="prod", detected_at=_T
    )
    findings = normalize_live_polaris(pf, envelope=_envelope(), scan_time=_T)
    assert findings and _all_2003(findings)


def test_kubelet_runtime_pipeline_emits_2003() -> None:
    pods = enumerate_pods(KubeletClient(_Transport()).pods())
    violations = evaluate_runtime_posture(pods)
    findings = emit_runtime_findings(violations, envelope=_envelope(), scan_time=_T)
    assert findings and _all_2003(findings)
    assert any(v.rule_id == "privileged-container" for v in violations)


def test_rbac_pipeline_emits_2003() -> None:
    roles = enumerate_roles([_ROLE])
    over = detect_over_privileged(roles, enumerate_bindings([]))
    findings = emit_rbac_findings(over, envelope=_envelope(), scan_time=_T)
    assert findings and _all_2003(findings)


def test_per_cluster_isolation_enforced() -> None:
    resolved = resolve_cluster(_KUBECONFIG)
    cluster_id = assert_single_cluster_context([resolved.cluster_id])
    session = ClusterScanSession(cluster_id)
    session.assert_belongs(resolved.cluster_id)  # in-cluster resource OK

    import pytest
    from k8s_posture.isolation import CrossClusterContextError

    with pytest.raises(CrossClusterContextError):
        session.assert_belongs("arn:aws:eks:us-east-1:1:cluster/other")


# --------------------------- gated-live layer ----------------------------


def test_live_cluster_reachable(k8s_gate: None) -> None:
    ok, reason = k8s_reachable()
    assert ok, f"cluster unreachable: {reason}"
