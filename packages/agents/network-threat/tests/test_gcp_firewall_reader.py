"""v0.5 Item 3 — GCP firewall live reader maps into the agnostic reach dataclasses."""

from network_threat.tools.gcp_firewall_reader import GcpFirewallReader
from network_threat.tools.reachability import reach_grants


class _FakeGcpFw:
    def list_instances(self):
        return [
            {"resource_id": "projects/p/zones/z/instances/web", "tags": ["tag-web"]},
            {"resource_id": "projects/p/zones/z/instances/db", "tags": ["tag-db"]},
        ]

    def list_firewalls(self):
        return [
            {
                "group_id": "tag-db",
                "ingress": [
                    {
                        "protocol": "tcp",
                        "from_port": 5432,
                        "to_port": 5432,
                        "source_sgs": ["tag-web"],
                    }
                ],
            }
        ]


def test_reader_output_drives_reach_grants():
    insts, sgs = GcpFirewallReader(_FakeGcpFw()).read()
    out = reach_grants(insts, sgs)
    assert out[0][:2] == ("projects/p/zones/z/instances/web", "projects/p/zones/z/instances/db")
