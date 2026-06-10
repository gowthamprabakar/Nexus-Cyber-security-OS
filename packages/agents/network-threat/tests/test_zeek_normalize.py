"""D.4 v0.2 Task 6 — Zeek live event normalization tests."""

from __future__ import annotations

from datetime import UTC, datetime

from network_threat.schemas import DnsEvent, DnsEventKind
from network_threat.tools.zeek_normalize import (
    ZeekConn,
    normalize_zeek_conn,
    normalize_zeek_dns,
    normalize_zeek_event,
)

_RX = datetime(2026, 6, 11, tzinfo=UTC)

_CONN = {
    "_path": "conn",
    "ts": 1_700_000_000.0,
    "uid": "Cabc",
    "id.orig_h": "10.0.0.5",
    "id.orig_p": 44321,
    "id.resp_h": "1.2.3.4",
    "id.resp_p": 443,
    "proto": "tcp",
    "duration": 1.5,
    "orig_bytes": 1024,
    "resp_bytes": 2048,
    "conn_state": "SF",
}

_DNS = {
    "_path": "dns",
    "ts": 1_700_000_000.0,
    "id.orig_h": "10.0.0.5",
    "query": "Evil.Example.COM.",
    "qtype_name": "A",
    "rcode_name": "NOERROR",
}


def test_normalize_conn() -> None:
    c = normalize_zeek_conn(_CONN, received_at=_RX)
    assert isinstance(c, ZeekConn)
    assert c.uid == "Cabc" and c.src_ip == "10.0.0.5" and c.dst_port == 443
    assert c.orig_bytes == 1024 and c.resp_bytes == 2048 and c.conn_state == "SF"


def test_conn_missing_ip_returns_none() -> None:
    assert normalize_zeek_conn({"_path": "conn", "id.orig_h": "10.0.0.5"}, received_at=_RX) is None


def test_normalize_dns_to_dnsevent() -> None:
    d = normalize_zeek_dns(_DNS, received_at=_RX)
    assert isinstance(d, DnsEvent)
    assert d.query_name == "evil.example.com"  # lowercased, trailing dot stripped
    assert d.kind == DnsEventKind.RESPONSE  # rcode_name present
    assert d.src_ip == "10.0.0.5" and d.rcode == "NOERROR"


def test_dns_query_kind_when_no_rcode() -> None:
    d = normalize_zeek_dns({"query": "x.com"}, received_at=_RX)
    assert d is not None and d.kind == DnsEventKind.QUERY


def test_dns_missing_query_returns_none() -> None:
    assert normalize_zeek_dns({"_path": "dns"}, received_at=_RX) is None


def test_dispatch_by_path() -> None:
    assert isinstance(normalize_zeek_event(_CONN, received_at=_RX), ZeekConn)
    assert isinstance(normalize_zeek_event(_DNS, received_at=_RX), DnsEvent)


def test_unknown_path_returns_none() -> None:
    assert normalize_zeek_event({"_path": "http"}, received_at=_RX) is None


def test_conn_timestamp_from_epoch() -> None:
    c = normalize_zeek_conn(_CONN, received_at=_RX)
    assert c is not None  # ts parsed; conn keeps no datetime but dns does
    d = normalize_zeek_dns(_DNS, received_at=_RX)
    assert d is not None and d.timestamp.year == 2023  # 1.7e9 s ≈ 2023-11-14
