"""Red-team bank for derived reachability (CAN_REACH) — slice #2, the lateral-movement edge.

Precision crux (as in slice #1): a lateral reach edge is emitted ONLY when the dst SG's ingress
references a source SG that is actually held by a real instance, and src != dst. Traps (no ref /
dangling SG ref / CIDR-only / self) prove precision.
"""

from network_threat.tools.reachability import (
    IngressRule,
    NetworkInstance,
    SecurityGroup,
    reach_grants,
)

_A = "arn:aws:ec2:us-east-1:111:instance/i-web"
_B = "arn:aws:ec2:us-east-1:111:instance/i-db"


def _from_sg(src_sg: str, port: int = 5432) -> IngressRule:
    return IngressRule(protocol="tcp", from_port=port, to_port=port, source_sgs=(src_sg,))


def _from_cidr() -> IngressRule:
    # CIDR-only ingress carries no source SG → not a lateral edge (that's the internet leg).
    return IngressRule(protocol="tcp", from_port=443, to_port=443, source_sgs=())


# ----------------------------- standard reach → edge -----------------------------


def test_lateral_sg_reach_emits():
    instances = (NetworkInstance(_A, ("sg-web",)), NetworkInstance(_B, ("sg-db",)))
    sgs = (SecurityGroup("sg-db", (_from_sg("sg-web"),)),)
    assert reach_grants(instances, sgs) == [(_A, _B, "lateral_sg", "tcp:5432")]


def test_two_instances_sharing_source_sg_both_reach():
    a2 = _A + "-2"
    instances = (
        NetworkInstance(_A, ("sg-web",)),
        NetworkInstance(a2, ("sg-web",)),
        NetworkInstance(_B, ("sg-db",)),
    )
    sgs = (SecurityGroup("sg-db", (_from_sg("sg-web"),)),)
    srcs = {s for (s, _d, _m, _v) in reach_grants(instances, sgs)}
    assert srcs == {_A, a2}


def test_port_range_via_formatting():
    instances = (NetworkInstance(_A, ("sg-web",)), NetworkInstance(_B, ("sg-db",)))
    rule = IngressRule(protocol="tcp", from_port=8000, to_port=8100, source_sgs=("sg-web",))
    sgs = (SecurityGroup("sg-db", (rule,)),)
    assert reach_grants(instances, sgs)[0][3] == "tcp:8000-8100"


# ----------------------------- false-positive traps → NO edge -----------------------------


def test_trap_no_ingress_ref_no_edge():
    instances = (NetworkInstance(_A, ("sg-web",)), NetworkInstance(_B, ("sg-db",)))
    sgs = (SecurityGroup("sg-db", ()),)  # db SG admits no one
    assert reach_grants(instances, sgs) == []


def test_trap_dangling_sg_ref_no_edge():
    # db SG references sg-bastion, but NO instance holds sg-bastion → no dangling edge.
    instances = (NetworkInstance(_A, ("sg-web",)), NetworkInstance(_B, ("sg-db",)))
    sgs = (SecurityGroup("sg-db", (_from_sg("sg-bastion"),)),)
    assert reach_grants(instances, sgs) == []


def test_trap_cidr_only_ingress_is_not_lateral():
    instances = (NetworkInstance(_A, ("sg-web",)), NetworkInstance(_B, ("sg-db",)))
    sgs = (SecurityGroup("sg-db", (_from_cidr(),)),)
    assert reach_grants(instances, sgs) == []


def test_trap_self_reach_excluded():
    # A single instance whose SG admits its own SG must not reach itself.
    instances = (NetworkInstance(_A, ("sg-web",)),)
    sgs = (SecurityGroup("sg-web", (_from_sg("sg-web"),)),)
    assert reach_grants(instances, sgs) == []
