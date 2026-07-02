"""NEX-401 — reach_grants is provider-agnostic: Azure NSG / GCP firewall map onto the SAME detector.

Slice #2 established that cross-cloud reachability is agnostic by construction (unlike privesc, which
has per-cloud role semantics). Rather than fake per-cloud clones, this proves the ONE detector handles
Azure-ASG-shaped and GCP-tag-shaped inputs (different id conventions, same function). The only per-cloud
work is the live reader that maps each cloud's model into these dataclasses — deferred (NEXUS_LIVE_*).
"""

from network_threat.tools.reachability import (
    IngressRule,
    NetworkInstance,
    SecurityGroup,
    VpcInstance,
    peering_reach_grants,
    reach_grants,
)


def test_azure_asg_shaped_lateral():
    # Azure: NICs in Application Security Groups; a rule admits a source ASG. Same shape as SG-to-SG.
    insts = (
        NetworkInstance("/subscriptions/s/vm/web", ("asg-web",)),
        NetworkInstance("/subscriptions/s/vm/db", ("asg-db",)),
    )
    sgs = (SecurityGroup("asg-db", (IngressRule("Tcp", 1433, 1433, ("asg-web",)),)),)
    out = reach_grants(insts, sgs)
    assert out == [("/subscriptions/s/vm/web", "/subscriptions/s/vm/db", "lateral_sg", "Tcp:1433")]


def test_gcp_tag_shaped_lateral():
    # GCP: instances carry network tags; a firewall rule's target/source are tags. Same shape.
    insts = (
        NetworkInstance("projects/p/zones/z/instances/web", ("tag-web",)),
        NetworkInstance("projects/p/zones/z/instances/db", ("tag-db",)),
    )
    sgs = (SecurityGroup("tag-db", (IngressRule("tcp", 5432, 5432, ("tag-web",)),)),)
    out = reach_grants(insts, sgs)
    assert out[0][:2] == ("projects/p/zones/z/instances/web", "projects/p/zones/z/instances/db")


def test_peering_agnostic_across_clouds():
    # VPC peering / VNet peering / VPC Network Peering — all just "two networks are peered".
    az = peering_reach_grants(
        (VpcInstance("az-a", "vnet-a"), VpcInstance("az-b", "vnet-b")),
        frozenset({frozenset({"vnet-a", "vnet-b"})}),
    )
    assert {(s, d) for s, d, _m, _v in az} == {("az-a", "az-b"), ("az-b", "az-a")}
