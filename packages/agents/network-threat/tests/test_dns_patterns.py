"""D.4 v0.2 Task 12 — DNS query pattern detection tests."""

from __future__ import annotations

from datetime import UTC, datetime

from network_threat.detectors.dns_patterns import (
    has_suspicious_tld,
    is_dns_tunneling,
    repeated_query_domains,
)
from network_threat.schemas import DnsEvent, DnsEventKind

_TS = datetime(2026, 6, 11, tzinfo=UTC)


def _dns(query: str) -> DnsEvent:
    return DnsEvent(timestamp=_TS, kind=DnsEventKind.QUERY, query_name=query, src_ip="10.0.0.5")


def test_suspicious_tld() -> None:
    assert has_suspicious_tld("evil.tk") is True
    assert has_suspicious_tld("login.xyz") is True
    assert has_suspicious_tld("google.com") is False


def test_dns_tunneling_long_label() -> None:
    long_label = "a" * 55
    assert is_dns_tunneling(f"{long_label}.tunnel.example.com") is True


def test_dns_tunneling_normal_domain_not_flagged() -> None:
    assert is_dns_tunneling("www.google.com") is False


def test_dns_tunneling_many_long_labels() -> None:
    # 4+ labels and overall length large → tunneling.
    q = ".".join(["abcdefghijkl"] * 5) + ".example.com"
    assert is_dns_tunneling(q) is True


def test_dns_tunneling_empty() -> None:
    assert is_dns_tunneling("") is False


def test_repeated_query_domains() -> None:
    events = [_dns("c2.evil.tk")] * 12 + [_dns("google.com")] * 3
    out = repeated_query_domains(events, min_count=10)
    assert out == [("c2.evil.tk", 12)]  # google.com below threshold


def test_repeated_query_sorted_by_count() -> None:
    events = [_dns("a.com")] * 15 + [_dns("b.com")] * 20
    out = repeated_query_domains(events, min_count=10)
    assert [d for d, _ in out] == ["b.com", "a.com"]  # 20 before 15


def test_repeated_query_empty() -> None:
    assert repeated_query_domains([]) == []
