"""v0.5 Item 3 — Azure NSG live reader maps into the agnostic reach dataclasses."""

from network_threat.tools.azure_nsg_reader import AzureNsgReader
from network_threat.tools.reachability import reach_grants


class _FakeNsgClient:
    def list_nics(self):
        return [
            {"resource_id": "/subscriptions/s/vm/web", "asgs": ["asg-web"]},
            {"resource_id": "/subscriptions/s/vm/db", "asgs": ["asg-db"]},
        ]

    def list_security_groups(self):
        return [
            {
                "group_id": "asg-db",
                "ingress": [
                    {
                        "protocol": "Tcp",
                        "from_port": 1433,
                        "to_port": 1433,
                        "source_sgs": ["asg-web"],
                    }
                ],
            }
        ]


def test_reader_output_drives_reach_grants():
    insts, sgs = AzureNsgReader(_FakeNsgClient()).read()
    out = reach_grants(insts, sgs)
    assert out == [("/subscriptions/s/vm/web", "/subscriptions/s/vm/db", "lateral_sg", "Tcp:1433")]
