"""ELBv2 (ALB/NLB) internet-exposure reader (gap #10 — load-balancer exposure).

A workload behind a public load balancer is internet-reachable even with no public IP and a
closed instance security group — the common production pattern the SG-only check missed. This
returns the **target groups served by an internet-facing load balancer**; the ECS/EC2 readers
OR that into a workload's ``is_public`` (an ECS service references its target group via the
service ``loadBalancers`` field; an instance is registered as a target).

Traversal: ``describe_load_balancers`` (Scheme ``internet-facing``) → ``describe_listeners`` →
each listener's ``DefaultActions[].TargetGroupArn``. (The ``TargetGroup.LoadBalancerArns``
back-reference is not always populated, so we walk LB → listeners forward.)
"""

from __future__ import annotations


def internet_facing_target_groups(elbv2: object) -> frozenset[str]:
    """Target-group ARNs served by an internet-facing ALB/NLB (via its listeners)."""
    out: set[str] = set()
    for lb in elbv2.describe_load_balancers().get("LoadBalancers", []):  # type: ignore[attr-defined]
        if lb.get("Scheme") != "internet-facing":
            continue
        listeners = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"]).get(  # type: ignore[attr-defined]
            "Listeners", []
        )
        for listener in listeners:
            for action in listener.get("DefaultActions", []):
                tg = action.get("TargetGroupArn")
                if tg:
                    out.add(tg)
    return frozenset(out)


__all__ = ["internet_facing_target_groups"]
