"""CIS Kubernetes Benchmark v1.8 reference catalog (D.6 v0.2 Task 4).

Broadens v0.1's ~v1.5 subset to a **v1.8** control catalog: a reference map of kube-bench
control ids → CIS v1.8 metadata (title + profile level + scored flag) so live findings can
be enriched with the benchmark version + level. **Additive** — a lookup catalog, not a
change to the v0.1 detectors / eval (WI-K5 byte-identical).
"""

from __future__ import annotations

from dataclasses import dataclass

BENCHMARK_VERSION = "1.8"


@dataclass(frozen=True, slots=True)
class CisControl:
    control_id: str
    title: str
    level: int  # CIS profile level: 1 or 2
    scored: bool = True


def _c(control_id: str, title: str, level: int, scored: bool = True) -> CisControl:
    return CisControl(control_id=control_id, title=title, level=level, scored=scored)


#: A representative CIS K8s v1.8 control catalog spanning the benchmark sections
#: (1.x control plane · 2.x etcd · 3.x control-plane config · 4.x worker node · 5.x policies).
CIS_K8S_V18: dict[str, CisControl] = {
    c.control_id: c
    for c in (
        # 1.x — Control Plane Components
        _c("1.2.1", "Ensure that the --anonymous-auth argument is set to false", 1),
        _c("1.2.5", "Ensure that the --kubelet-certificate-authority argument is set", 1),
        _c("1.2.16", "Ensure that the --profiling argument is set to false", 1),
        _c("1.3.2", "Ensure that the --profiling argument is set to false (controller-manager)", 1),
        _c("1.4.1", "Ensure that the --profiling argument is set to false (scheduler)", 1),
        # 2.x — etcd
        _c("2.1", "Ensure that the --cert-file and --key-file arguments are set for etcd", 1),
        _c("2.2", "Ensure that the --client-cert-auth argument is set to true for etcd", 1),
        # 3.x — Control Plane Configuration
        _c("3.2.1", "Ensure that a minimal audit policy is created", 1),
        # 4.x — Worker Nodes
        _c("4.2.1", "Ensure that the --anonymous-auth argument is set to false (kubelet)", 1),
        _c("4.2.6", "Ensure that the --make-iptables-util-chains argument is set to true", 1),
        # 5.x — Policies
        _c("5.1.1", "Ensure that the cluster-admin role is only used where required", 1),
        _c("5.1.5", "Ensure that default service accounts are not actively used", 1),
        _c("5.2.2", "Minimize the admission of privileged containers", 2),
        _c("5.2.6", "Minimize the admission of root containers", 2),
        _c("5.3.2", "Ensure that all Namespaces have Network Policies defined", 2),
    )
}


def lookup(control_id: str) -> CisControl | None:
    """Look up a CIS v1.8 control by its kube-bench control id."""
    return CIS_K8S_V18.get(control_id)


def cis_level(control_id: str) -> int | None:
    """The CIS profile level (1 or 2) for a control, or `None` if not in the catalog."""
    control = CIS_K8S_V18.get(control_id)
    return control.level if control is not None else None
