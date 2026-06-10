"""Zeek + Suricata cross-sensor correlation (D.4 v0.2 Task 7).

When Zeek and Suricata both observe the **same connection** (4-tuple + protocol), they're
reporting on the same network activity. This correlator joins their typed records by
``(src_ip, src_port, dst_ip, dst_port, proto)`` so downstream emits **one** correlated
finding (cross-sensor = higher confidence) instead of two duplicates. Mirrors D.3's
Falco x Tracee cross-sensor correlator (Group A precedent).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from network_threat.schemas import SuricataAlert
from network_threat.tools.zeek_normalize import ZeekConn


@dataclass(frozen=True, slots=True)
class ConnectionKey:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str  # lowercased


@dataclass
class CorrelatedNetworkEvent:
    key: ConnectionKey
    suricata: list[SuricataAlert] = field(default_factory=list)
    zeek: list[ZeekConn] = field(default_factory=list)

    @property
    def cross_sensor(self) -> bool:
        """True iff BOTH sensors fired on this connection (higher confidence)."""
        return bool(self.suricata) and bool(self.zeek)

    @property
    def event_count(self) -> int:
        return len(self.suricata) + len(self.zeek)


def suricata_key(alert: SuricataAlert) -> ConnectionKey:
    return ConnectionKey(
        alert.src_ip, alert.src_port, alert.dst_ip, alert.dst_port, alert.protocol.lower()
    )


def zeek_key(conn: ZeekConn) -> ConnectionKey:
    return ConnectionKey(conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port, conn.proto.lower())


def correlate_network_events(
    suricata: list[SuricataAlert], zeek: list[ZeekConn]
) -> list[CorrelatedNetworkEvent]:
    """Group Suricata alerts + Zeek conns by the connection 4-tuple + protocol."""
    groups: dict[ConnectionKey, CorrelatedNetworkEvent] = {}
    for a in suricata:
        groups.setdefault(
            suricata_key(a), CorrelatedNetworkEvent(key=suricata_key(a))
        ).suricata.append(a)
    for c in zeek:
        groups.setdefault(zeek_key(c), CorrelatedNetworkEvent(key=zeek_key(c))).zeek.append(c)
    return list(groups.values())


def cross_sensor_events(
    correlated: list[CorrelatedNetworkEvent],
) -> list[CorrelatedNetworkEvent]:
    """The subset where both sensors fired (the de-duplicated, higher-confidence groups)."""
    return [c for c in correlated if c.cross_sensor]
