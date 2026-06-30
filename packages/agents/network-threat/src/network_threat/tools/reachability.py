"""Derived network reachability (CAN_REACH) — slice #2, the lateral-movement edge.

The network-threat flow writer records only *observed* traffic (``COMMUNICATES_WITH``). This is the
*derived* reachability decision #715a parked as Stage 3: from security-group config alone, who CAN
reach whom even if no flow has been seen yet. The high-value shape is **lateral movement** — an
instance whose security group's ingress allows another instance's security group can be reached from
it, so a foothold on a public box can pivot to a private one.

Provider-agnostic edge *contract* (the same 4-tuple slice #1 uses):
``(src_resource_id, dst_resource_id, method, via)`` with ``method="lateral_sg"``. AWS is the first
implementation; Azure NSG / GCP firewall are the same edge on other clouds.

Inputs are injectable frozen dataclasses (unit-testable without boto3); the live
``describe-security-groups`` reader is the operator-gated follow-on, as with slice #1's live lanes.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IngressRule:
    """One security-group ingress rule. ``source_sgs`` are referenced SGs (the lateral leg);
    ``from_port``/``to_port`` are ``None`` for all-ports / icmp."""

    protocol: str
    from_port: int | None
    to_port: int | None
    source_sgs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SecurityGroup:
    group_id: str
    ingress: tuple[IngressRule, ...]


@dataclass(frozen=True, slots=True)
class NetworkInstance:
    """A reachable resource keyed by its graph node id (ARN/instance-id) + the SGs it belongs to."""

    resource_id: str
    security_group_ids: tuple[str, ...]


def _via(rule: IngressRule) -> str:
    if rule.from_port is None:
        return f"{rule.protocol}:all"
    if rule.from_port == rule.to_port:
        return f"{rule.protocol}:{rule.from_port}"
    return f"{rule.protocol}:{rule.from_port}-{rule.to_port}"


def reach_grants(
    instances: tuple[NetworkInstance, ...], security_groups: tuple[SecurityGroup, ...]
) -> list[tuple[str, str, str, str]]:
    """``(src_resource_id, dst_resource_id, "lateral_sg", via)`` for each SG-allowed lateral reach.

    ``dst``'s security group has an ingress rule referencing a source SG that ``src`` belongs to, so
    ``src`` can reach ``dst`` over the network. The precision crux (as in slice #1): an edge is
    emitted ONLY when the referenced source SG is actually held by a real instance — no dangling
    edges to unused SGs — and ``src != dst``. Deduped on ``(src, dst, via)``, order-stable.
    """
    members: dict[str, list[str]] = {}
    for inst in instances:
        for sg_id in inst.security_group_ids:
            members.setdefault(sg_id, []).append(inst.resource_id)
    sg_by_id = {sg.group_id: sg for sg in security_groups}

    out: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for dst in instances:
        for sg_id in dst.security_group_ids:
            sg = sg_by_id.get(sg_id)
            if sg is None:
                continue
            for rule in sg.ingress:
                via = _via(rule)
                for src_sg in rule.source_sgs:
                    for src_id in members.get(src_sg, ()):
                        key = (src_id, dst.resource_id, via)
                        if src_id != dst.resource_id and key not in seen:
                            seen.add(key)
                            out.append((src_id, dst.resource_id, "lateral_sg", via))
    return out


__all__ = ["IngressRule", "NetworkInstance", "SecurityGroup", "reach_grants"]
