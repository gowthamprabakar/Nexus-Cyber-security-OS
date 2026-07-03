"""v0.5 Item 3 — GCP firewall -> agnostic reach dataclasses (operator-gated live leg).

GCP instances carry network tags; a firewall rule's target/source are tags. Same agnostic mapping
as Azure (Task 11): tags become `security_group_ids`, a rule's source tags become
`IngressRule.source_sgs`. Injectable `GcpFirewallClient` -> unit-testable without the gcp sdk.
"""

from __future__ import annotations

from typing import Any, Protocol

from network_threat.tools.reachability import IngressRule, NetworkInstance, SecurityGroup


class GcpFirewallClient(Protocol):
    def list_instances(self) -> list[dict[str, Any]]: ...
    def list_firewalls(self) -> list[dict[str, Any]]: ...


def _int_or_none(v: Any) -> int | None:
    return int(v) if isinstance(v, (int, str)) and str(v).isdigit() else None


class GcpFirewallReader:
    """Reads live GCP firewall topology via an injectable client into the agnostic reach dataclasses."""

    __slots__ = ("_client",)

    def __init__(self, client: GcpFirewallClient) -> None:
        self._client = client

    def read(self) -> tuple[tuple[NetworkInstance, ...], tuple[SecurityGroup, ...]]:
        insts = tuple(
            NetworkInstance(str(i["resource_id"]), tuple(str(tg) for tg in i.get("tags", [])))
            for i in self._client.list_instances()
            if i.get("resource_id")
        )
        sgs = tuple(
            SecurityGroup(
                str(g["group_id"]),
                tuple(
                    IngressRule(
                        str(r.get("protocol", "")),
                        _int_or_none(r.get("from_port")),
                        _int_or_none(r.get("to_port")),
                        tuple(str(s) for s in r.get("source_sgs", [])),
                    )
                    for r in g.get("ingress", [])
                ),
            )
            for g in self._client.list_firewalls()
            if g.get("group_id")
        )
        return insts, sgs


__all__ = ["GcpFirewallClient", "GcpFirewallReader"]
