"""D.4 v0.2 Task 10 — flow anomaly detection + static-intel uplift tests."""

from __future__ import annotations

from network_threat.detectors.flow_anomaly import (
    ConnectionRateAnomaly,
    connection_rate_anomalies,
    intel_tags,
    is_known_bad,
    is_tor_exit,
)
from network_threat.tools.vpc_flow_normalize import FlowAggregate


def _agg(src: str, dst: str, port: int) -> FlowAggregate:
    return FlowAggregate(
        src, dst, port, 6, flow_count=1, total_bytes=100, total_packets=1, accepted=1, rejected=0
    )


def test_connection_rate_flags_high_fanout() -> None:
    aggs = [_agg("10.0.0.5", f"1.2.3.{i}", 443) for i in range(25)]
    [anom] = connection_rate_anomalies(aggs, min_distinct_destinations=20)
    assert isinstance(anom, ConnectionRateAnomaly)
    assert anom.src_ip == "10.0.0.5" and anom.distinct_destinations == 25 and anom.total_flows == 25


def test_below_threshold_not_flagged() -> None:
    aggs = [_agg("10.0.0.5", f"1.2.3.{i}", 443) for i in range(5)]
    assert connection_rate_anomalies(aggs, min_distinct_destinations=20) == []


def test_distinct_counts_dest_ip_and_port() -> None:
    # Same dst_ip but different ports count as distinct destinations.
    aggs = [_agg("10.0.0.5", "1.2.3.4", p) for p in range(20)]
    [anom] = connection_rate_anomalies(aggs, min_distinct_destinations=20)
    assert anom.distinct_destinations == 20


def test_multiple_sources_sorted_by_fanout() -> None:
    aggs = [_agg("10.0.0.5", f"1.2.3.{i}", 443) for i in range(30)]
    aggs += [_agg("10.0.0.6", f"4.5.6.{i}", 443) for i in range(22)]
    anoms = connection_rate_anomalies(aggs, min_distinct_destinations=20)
    assert [a.src_ip for a in anoms] == ["10.0.0.5", "10.0.0.6"]  # 30 before 22


def test_empty() -> None:
    assert connection_rate_anomalies([]) == []


def test_is_tor_exit() -> None:
    assert is_tor_exit("185.220.101.1") is True and is_tor_exit("8.8.8.8") is False


def test_is_known_bad() -> None:
    assert is_known_bad("45.135.232.1") is True and is_known_bad("8.8.8.8") is False


def test_intel_tags() -> None:
    assert intel_tags("185.220.101.1") == ("tor-exit",)
    assert intel_tags("45.135.232.1") == ("known-bad",)
    assert intel_tags("8.8.8.8") == ()
