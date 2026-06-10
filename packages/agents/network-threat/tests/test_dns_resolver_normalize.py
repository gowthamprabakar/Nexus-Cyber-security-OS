"""D.4 v0.2 Task 13 — DNS resolver live normalization tests."""

from __future__ import annotations

from network_threat.schemas import DnsEvent, DnsEventKind
from network_threat.tools.dns_resolver_normalize import (
    normalize_bind_line,
    normalize_resolver_event,
    normalize_route53_line,
    normalize_route53_record,
)

_BIND = (
    "13-May-2026 12:00:00.123 queries: info: client @0x7f 10.0.1.42#54321 "
    "(malicious.xyz): query: malicious.xyz IN A +E(0)K (10.0.1.1)"
)

_R53 = {
    "query_timestamp": "2026-06-11T12:00:00Z",
    "query_name": "evil.tk",
    "query_type": "A",
    "srcaddr": "10.0.0.5",
    "vpc_id": "vpc-1",
    "rcode": "NOERROR",
    "answers": [],
}


def test_normalize_bind_line() -> None:
    e = normalize_bind_line(_BIND)
    assert isinstance(e, DnsEvent)
    assert e.query_name == "malicious.xyz" and e.src_ip == "10.0.1.42"
    assert e.kind == DnsEventKind.QUERY


def test_bind_malformed_returns_none() -> None:
    assert normalize_bind_line("not a bind line") is None


def test_normalize_route53_record() -> None:
    e = normalize_route53_record(_R53)
    assert isinstance(e, DnsEvent)
    assert e.query_name == "evil.tk" and e.src_ip == "10.0.0.5"


def test_route53_with_answers_is_response() -> None:
    rec = dict(_R53)
    rec["answers"] = [{"Rdata": "1.2.3.4"}]
    e = normalize_route53_record(rec)
    assert e is not None and e.kind == DnsEventKind.RESPONSE


def test_normalize_route53_line() -> None:
    import json

    e = normalize_route53_line(json.dumps(_R53))
    assert e is not None and e.query_name == "evil.tk"


def test_route53_malformed_returns_none() -> None:
    assert normalize_route53_line("{ not json") is None


def test_dispatch_bind() -> None:
    assert isinstance(normalize_resolver_event(_BIND, source="bind"), DnsEvent)


def test_dispatch_route53() -> None:
    import json

    assert isinstance(normalize_resolver_event(json.dumps(_R53), source="route53"), DnsEvent)


def test_dispatch_unknown_source() -> None:
    assert normalize_resolver_event(_BIND, source="bogus") is None
