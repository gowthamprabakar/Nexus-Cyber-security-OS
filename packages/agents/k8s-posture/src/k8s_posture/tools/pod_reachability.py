"""Pod-to-pod reachability (W4) — the Kubernetes lateral-movement edge (POD_CAN_REACH).

Kubernetes networking is default-ALLOW: absent a NetworkPolicy that selects a pod for ingress, every
pod in its namespace can reach it. A flat namespace with no segmentation is a lateral-movement
highway — a compromised pod can pivot to any neighbour (and from there to the neighbour's service
account / cloud role, or a neighbour running a vulnerable image).

``pod_reach_grants`` emits ``(src_pod_id, dst_pod_id)`` for same-namespace pairs whose destination is
NOT ingress-isolated. Isolation is a caller-supplied fact (a restrictive NetworkPolicy selects the
pod) so the detector stays a pure function; the live NetworkPolicy reader is the operator-gated
follow-on. ponytail: O(n²) edges per namespace — a real cluster caps this by only emitting FROM
source-marked pods, a later optimisation; the model here is the honest default-allow semantics.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PodRef:
    """A pod on the graph: its node id (``cluster/namespace/pod/name``) + namespace + isolation."""

    pod_id: str
    namespace: str
    #: True if a restrictive NetworkPolicy selects this pod for ingress (not default-reachable).
    isolated: bool = False


def pod_reach_grants(pods: tuple[PodRef, ...]) -> list[tuple[str, str]]:
    """``(src_pod_id, dst_pod_id)`` for each same-namespace pair whose dst is not ingress-isolated.

    Default-allow K8s semantics: any pod reaches any non-isolated pod in its namespace. Cross-
    namespace pairs and isolated destinations are excluded (the precision crux); no self-edges.
    Deduped, order-stable.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for dst in pods:
        if dst.isolated:
            continue
        for src in pods:
            if src.pod_id == dst.pod_id or src.namespace != dst.namespace:
                continue
            grant = (src.pod_id, dst.pod_id)
            if grant not in seen:
                seen.add(grant)
                out.append(grant)
    return out


__all__ = ["PodRef", "pod_reach_grants"]
