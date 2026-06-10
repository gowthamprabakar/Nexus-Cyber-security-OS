"""Flow anomaly detection + static-intel uplift (D.4 v0.2 Task 10).

Adds a **connection-rate** anomaly detector over the Task-9 flow aggregates (a single
source fanning out to many distinct destinations — a sweep/scan indicator) plus a
**static-intel uplift** (bundled Tor-exit + known-bad IP sets with lookups). Both are
**new + additive** — the v0.1 port_scan / beacon / dga detectors + their eval cases are
untouched (WI-N5 byte-identical).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from network_threat.tools.vpc_flow_normalize import FlowAggregate

#: Static-intel uplift — small bundled sets (additive; do NOT touch the v0.1 intel lists).
TOR_EXIT_NODES = frozenset({"185.220.101.1", "185.220.101.2", "204.13.164.118"})
KNOWN_BAD_IPS = frozenset({"45.135.232.1", "193.142.146.35"})


def is_tor_exit(ip: str) -> bool:
    return ip in TOR_EXIT_NODES


def is_known_bad(ip: str) -> bool:
    return ip in KNOWN_BAD_IPS


def intel_tags(ip: str) -> tuple[str, ...]:
    """Static-intel tags for an IP (``tor-exit`` / ``known-bad``), empty when clean."""
    tags: list[str] = []
    if is_tor_exit(ip):
        tags.append("tor-exit")
    if is_known_bad(ip):
        tags.append("known-bad")
    return tuple(tags)


@dataclass(frozen=True, slots=True)
class ConnectionRateAnomaly:
    src_ip: str
    distinct_destinations: int
    total_flows: int


def connection_rate_anomalies(
    aggregates: Sequence[FlowAggregate], *, min_distinct_destinations: int = 20
) -> list[ConnectionRateAnomaly]:
    """Flag source IPs that contacted at least ``min_distinct_destinations`` distinct
    ``(dst_ip, dst_port)`` pairs — a connection-rate sweep indicator. Sorted by fan-out."""
    dests_by_src: dict[str, set[tuple[str, int]]] = {}
    flows_by_src: dict[str, int] = {}
    for a in aggregates:
        dests_by_src.setdefault(a.src_ip, set()).add((a.dst_ip, a.dst_port))
        flows_by_src[a.src_ip] = flows_by_src.get(a.src_ip, 0) + a.flow_count

    out = [
        ConnectionRateAnomaly(src, len(dests), flows_by_src[src])
        for src, dests in dests_by_src.items()
        if len(dests) >= min_distinct_destinations
    ]
    out.sort(key=lambda x: (-x.distinct_destinations, x.src_ip))
    return out
