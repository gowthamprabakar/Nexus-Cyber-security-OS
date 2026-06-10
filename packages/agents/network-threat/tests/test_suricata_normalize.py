"""D.4 v0.2 Task 3 — Suricata live alert normalization tests."""

from __future__ import annotations

from datetime import UTC, datetime

from network_threat.tools.suricata_normalize import normalize_suricata_event

_RX = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)

_RAW = {
    "event_type": "alert",
    "timestamp": "2026-06-11T11:59:00.000000+0000",
    "src_ip": "10.0.0.5",
    "dest_ip": "198.51.100.7",
    "src_port": 44321,
    "dest_port": 443,
    "proto": "TCP",
    "alert": {
        "signature_id": 2019401,
        "signature": "ET MALWARE Suspicious TLS",
        "category": "A Network Trojan was detected",
        "severity": 1,
        "rev": 3,
        "action": "allowed",
    },
}


def test_normalize_full_alert() -> None:
    norm = normalize_suricata_event(_RAW, received_at=_RX)
    assert norm is not None
    a = norm.alert
    assert a.src_ip == "10.0.0.5" and a.dst_ip == "198.51.100.7"
    assert a.src_port == 44321 and a.dst_port == 443 and a.protocol == "TCP"
    assert a.signature_id == 2019401 and a.signature == "ET MALWARE Suspicious TLS"


def test_enrichment() -> None:
    e = normalize_suricata_event(_RAW, received_at=_RX).enrichment
    assert e.signature_id == 2019401
    assert e.classtype == "A Network Trojan was detected"
    assert e.action == "allowed" and e.severity


def test_non_alert_event_returns_none() -> None:
    assert normalize_suricata_event({"event_type": "dns"}, received_at=_RX) is None


def test_missing_alert_blob_returns_none() -> None:
    assert normalize_suricata_event({"event_type": "alert"}, received_at=_RX) is None


def test_missing_required_field_returns_none() -> None:
    bad = {"event_type": "alert", "alert": {"severity": 1, "signature_id": 1, "signature": "x"}}
    # No src_ip/dst_ip (min_length 1) → validation fails → None (forgiving).
    assert normalize_suricata_event(bad, received_at=_RX) is None


def test_missing_timestamp_uses_received_at() -> None:
    raw = dict(_RAW)
    raw.pop("timestamp")
    norm = normalize_suricata_event(raw, received_at=_RX)
    assert norm is not None and norm.alert.timestamp == _RX


def test_byte_identical_with_offline_path() -> None:
    # The live normalize from a dict matches the offline reader's parse from a JSON line.
    import json

    from network_threat.tools.suricata_reader import _try_parse_line

    offline = _try_parse_line(json.dumps(_RAW))
    live = normalize_suricata_event(_RAW, received_at=_RX)
    assert offline is not None and live is not None
    assert live.alert.model_dump() == offline.model_dump()
