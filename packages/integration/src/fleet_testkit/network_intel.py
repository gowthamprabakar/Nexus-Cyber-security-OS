"""In-memory network + threat-intel harness — cross-domain path A1 (network/threat-intel feeders).

Network flows come from VPC Flow Logs and IOCs from threat feeds; both are the agents' native
*parsed* input types (``FlowRecord`` / ``IocEntity``). These drivers construct those types and run
the agents' REAL writers (``network_threat.record_flows`` / ``threat_intel.upsert_ioc``) into a
store, so the cross-agent correlation resolvers + the malicious-destination detector fire on real
agent output. The owning-resource (EC2 instance) comes from moto — see ``moto_aws`` drivers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from network_threat.kg_writer import KnowledgeGraphWriter as NetworkKgWriter
from network_threat.schemas import FlowRecord
from threat_intel.entities import IocEntity
from threat_intel.kg_writer import KnowledgeGraphWriter as ThreatIntelKgWriter
from threat_intel.schemas import IocType

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

# A fixed observation window (tests must not use wall-clock time).
_T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 1, 1, 0, 5, 0, tzinfo=UTC)


async def drive_network_flows(
    store: SemanticStore, *, tenant_id: str, flows: tuple[tuple[str, str], ...]
) -> None:
    """Run network-threat's REAL ``record_flows`` for each ``(src_ip, dst_ip)`` flow."""
    records = [
        FlowRecord(
            src_ip=src,
            dst_ip=dst,
            src_port=44321,
            dst_port=443,
            protocol=6,
            bytes_transferred=4096,
            packets=12,
            start_time=_T0,
            end_time=_T1,
            action="ACCEPT",
        )
        for src, dst in flows
    ]
    await NetworkKgWriter(store, tenant_id).record_flows(records)


async def drive_threat_intel_iocs(
    store: SemanticStore, *, tenant_id: str, malicious_ips: tuple[str, ...]
) -> None:
    """Run threat-intel's REAL ``upsert_ioc`` for each known-malicious IP (an IOC of type ip)."""
    writer = ThreatIntelKgWriter(store, tenant_id)
    for ip in malicious_ips:
        await writer.upsert_ioc(
            IocEntity(
                ioc_type=IocType.IP,
                value=ip,
                first_seen=_T0,
                last_seen=_T1,
                source_feed="test-feed",
            )
        )


__all__ = ["drive_network_flows", "drive_threat_intel_iocs"]
