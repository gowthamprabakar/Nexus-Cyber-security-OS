"""VPC Flow Log normalization + aggregation (D.4 v0.2 Task 9).

Builds on the live reader (Task 8): a single-message parser with a configurable field
order (**v2-v5** support, reusing the shared offline parser so records stay byte-
identical), plus **source/dest/port aggregation** that rolls many flow records up to
per-connection stats for the anomaly detectors.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from network_threat.schemas import FlowRecord
from network_threat.tools.vpc_flow_reader import _V2_DEFAULT_FIELDS, _try_parse_record


def parse_flow_message(
    message: str, *, fields: tuple[str, ...] = _V2_DEFAULT_FIELDS
) -> FlowRecord | None:
    """Parse a single CloudWatch VPC-flow message with a configurable field order
    (v2 default; pass a v3/v4/v5 field tuple for custom formats). Returns `None` if
    malformed."""
    return _try_parse_record(message.split(), fields)


@dataclass(frozen=True, slots=True)
class FlowAggregate:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: int
    flow_count: int
    total_bytes: int
    total_packets: int
    accepted: int
    rejected: int


def aggregate_flows(records: Sequence[FlowRecord]) -> list[FlowAggregate]:
    """Roll flow records up by ``(src_ip, dst_ip, dst_port, protocol)`` — summing bytes /
    packets / flow-count and counting ACCEPT vs REJECT — for the anomaly detectors."""
    acc: dict[tuple[str, str, int, int], dict[str, int]] = {}
    for r in records:
        key = (r.src_ip, r.dst_ip, r.dst_port, r.protocol)
        a = acc.setdefault(
            key, {"flows": 0, "bytes": 0, "packets": 0, "accepted": 0, "rejected": 0}
        )
        a["flows"] += 1
        a["bytes"] += r.bytes_transferred
        a["packets"] += r.packets
        if r.action == "ACCEPT":
            a["accepted"] += 1
        elif r.action == "REJECT":
            a["rejected"] += 1
    return [
        FlowAggregate(
            src_ip=k[0],
            dst_ip=k[1],
            dst_port=k[2],
            protocol=k[3],
            flow_count=v["flows"],
            total_bytes=v["bytes"],
            total_packets=v["packets"],
            accepted=v["accepted"],
            rejected=v["rejected"],
        )
        for k, v in acc.items()
    ]
