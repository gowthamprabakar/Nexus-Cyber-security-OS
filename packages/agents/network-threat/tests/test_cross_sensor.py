"""D.4 v0.2 Task 7 — Zeek + Suricata cross-sensor correlation tests."""

from __future__ import annotations

from datetime import UTC, datetime

from network_threat.correlators.cross_sensor import (
    correlate_network_events,
    cross_sensor_events,
)
from network_threat.schemas import SuricataAlert, SuricataAlertSeverity
from network_threat.tools.zeek_normalize import ZeekConn

_TS = datetime(2026, 6, 11, tzinfo=UTC)


def _alert(src_ip: str = "10.0.0.5", dst_ip: str = "1.2.3.4", dport: int = 443) -> SuricataAlert:
    return SuricataAlert(
        timestamp=_TS,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=44321,
        dst_port=dport,
        protocol="TCP",
        signature_id=42,
        signature="sig",
        category="cat",
        severity=SuricataAlertSeverity.HIGH,
        rev=1,
    )


def _conn(src_ip: str = "10.0.0.5", dst_ip: str = "1.2.3.4", dport: int = 443) -> ZeekConn:
    return ZeekConn(
        uid="C", src_ip=src_ip, src_port=44321, dst_ip=dst_ip, dst_port=dport, proto="tcp"
    )


def test_same_connection_correlates_to_one_group() -> None:
    groups = correlate_network_events([_alert()], [_conn()])
    assert len(groups) == 1 and groups[0].cross_sensor is True and groups[0].event_count == 2


def test_proto_case_insensitive_match() -> None:
    # Suricata "TCP" + Zeek "tcp" must land in the same group.
    [g] = correlate_network_events([_alert()], [_conn()])
    assert g.key.proto == "tcp"


def test_different_connections_stay_separate() -> None:
    groups = correlate_network_events([_alert(dport=443)], [_conn(dport=8080)])
    assert len(groups) == 2 and all(not g.cross_sensor for g in groups)


def test_suricata_only_group() -> None:
    [g] = correlate_network_events([_alert()], [])
    assert g.suricata and not g.zeek and g.cross_sensor is False


def test_zeek_only_group() -> None:
    [g] = correlate_network_events([], [_conn()])
    assert g.zeek and not g.suricata


def test_cross_sensor_filter() -> None:
    groups = correlate_network_events([_alert(dport=443), _alert(dport=22)], [_conn(dport=443)])
    cross = cross_sensor_events(groups)
    assert len(cross) == 1 and cross[0].key.dst_port == 443


def test_empty_inputs() -> None:
    assert correlate_network_events([], []) == []


def test_multiple_events_same_key_accumulate() -> None:
    [g] = correlate_network_events([_alert(), _alert()], [_conn()])
    assert len(g.suricata) == 2 and len(g.zeek) == 1 and g.event_count == 3
