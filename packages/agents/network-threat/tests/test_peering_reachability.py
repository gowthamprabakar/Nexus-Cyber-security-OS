"""NEX-302 red-team bank — cross-VPC peering reachability precision."""

from network_threat.tools.reachability import VpcInstance, peering_reach_grants

_PEER = frozenset({frozenset({"vpc-a", "vpc-b"})})


def test_peered_vpcs_reach_across():
    out = peering_reach_grants((VpcInstance("i-a", "vpc-a"), VpcInstance("i-b", "vpc-b")), _PEER)
    assert {(s, d) for s, d, _m, _v in out} == {("i-a", "i-b"), ("i-b", "i-a")}


def test_method_and_via():
    out = peering_reach_grants((VpcInstance("i-a", "vpc-a"), VpcInstance("i-b", "vpc-b")), _PEER)
    assert out[0][2] == "vpc_peering" and "vpc-a" in out[0][3]


# --- traps → no edge ---


def test_trap_unpeered_vpcs():
    assert (
        peering_reach_grants(
            (VpcInstance("i-a", "vpc-a"), VpcInstance("i-b", "vpc-b")), frozenset()
        )
        == []
    )


def test_trap_same_vpc_is_not_peering():
    # Same-VPC is reach_grants territory, not cross-VPC peering.
    out = peering_reach_grants((VpcInstance("i-a", "vpc-a"), VpcInstance("i-c", "vpc-a")), _PEER)
    assert out == []


def test_trap_no_self_edge():
    assert peering_reach_grants((VpcInstance("i-a", "vpc-a"),), _PEER) == []
