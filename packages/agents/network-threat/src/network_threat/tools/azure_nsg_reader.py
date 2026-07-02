"""v0.5 Item 3 — Azure NSG -> agnostic reach dataclasses (the operator-gated live leg).

`reach_grants` is provider-agnostic; the only per-cloud work is mapping each cloud's model into
`NetworkInstance`/`SecurityGroup`. This does that for Azure: a NIC's Application Security Groups
become an instance's `security_group_ids`, and an NSG rule admitting a source ASG becomes an
`IngressRule.source_sgs`. Injectable `AzureNsgClient` Protocol -> unit-testable without azure sdk.
The live client + its NEXUS_LIVE_AZURE lane is Task 14 (operator-run).
"""

from __future__ import annotations

from typing import Any, Protocol

from network_threat.tools.reachability import IngressRule, NetworkInstance, SecurityGroup


class AzureNsgClient(Protocol):
    def list_nics(self) -> list[dict[str, Any]]: ...
    def list_security_groups(self) -> list[dict[str, Any]]: ...


def _int_or_none(v: Any) -> int | None:
    return int(v) if isinstance(v, (int, str)) and str(v).isdigit() else None


class AzureNsgReader:
    """Reads live Azure NSG topology via an injectable client into the agnostic reach dataclasses."""

    __slots__ = ("_client",)

    def __init__(self, client: AzureNsgClient) -> None:
        self._client = client

    def read(self) -> tuple[tuple[NetworkInstance, ...], tuple[SecurityGroup, ...]]:
        insts = tuple(
            NetworkInstance(str(n["resource_id"]), tuple(str(a) for a in n.get("asgs", [])))
            for n in self._client.list_nics()
            if n.get("resource_id")
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
            for g in self._client.list_security_groups()
            if g.get("group_id")
        )
        return insts, sgs


__all__ = ["AzureNsgClient", "AzureNsgReader"]
