"""NEXUS_LIVE_K8S_POSTURE gated live-eval lane (D.6 v0.2 Task 17).

Consumes the hoisted charter Pattern D (`charter.live_lane`). Per **Q2** a **single** lane
covers all providers — EKS / AKS / GKE / self-managed are all reached through the
kubeconfig, so there's no per-provider gate. A DISTINCT gate from every prior cycle. The
reachability probe is injectable so it's testable without a live cluster.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from charter.live_lane import live_skip_reason, nexus_live_enabled

K8S_POSTURE_LIVE_ENV = "NEXUS_LIVE_K8S_POSTURE"
K8S_POSTURE_LIVE_SETUP = (
    "set NEXUS_LIVE_K8S_POSTURE=1 and point KUBECONFIG at a reachable cluster (EKS / AKS / "
    "GKE / self-managed — kubeconfig is the interface). e.g.: KUBECONFIG=~/.kube/config "
    "NEXUS_LIVE_K8S_POSTURE=1 uv run pytest "
    "packages/agents/k8s-posture/tests/integration/test_k8s_live_e2e.py -v"
)


def nexus_live_k8s_posture_enabled() -> bool:
    """True iff D.6's live K8s-posture lane is enabled (`NEXUS_LIVE_K8S_POSTURE=1`)."""
    return nexus_live_enabled(K8S_POSTURE_LIVE_ENV)


def _probe_k8s() -> tuple[bool, str]:
    """Probe cluster reachability via a configured, present kubeconfig (secret-free reason)."""
    kubeconfig = os.environ.get("KUBECONFIG", "")
    if not kubeconfig:
        return False, "KUBECONFIG-unset"
    return (
        os.path.exists(kubeconfig),
        "" if os.path.exists(kubeconfig) else "kubeconfig-not-found",
    )


def k8s_reachable(probe: Callable[[], tuple[bool, str]] = _probe_k8s) -> tuple[bool, str]:
    return probe()


def k8s_posture_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = k8s_reachable,
) -> str | None:
    return live_skip_reason(
        K8S_POSTURE_LIVE_ENV, "Kubernetes cluster API", K8S_POSTURE_LIVE_SETUP, probe
    )
