"""D.4 v0.2 Task 9 — VPC flow normalization + aggregation tests."""

from __future__ import annotations

from network_threat.tools.vpc_flow_normalize import (
    FlowAggregate,
    aggregate_flows,
    parse_flow_message,
)

# v2: version acct eni src dst sport dport proto packets bytes start end action status
_ACCEPT = (
    "2 123456789012 eni-a 10.0.0.5 1.2.3.4 44321 443 6 10 8400 1700000000 1700000060 ACCEPT OK"
)
_REJECT = "2 123456789012 eni-a 10.0.0.5 1.2.3.4 55000 443 6 2 120 1700000000 1700000060 REJECT OK"
_OTHER = "2 123456789012 eni-a 10.0.0.9 9.9.9.9 33000 22 6 1 60 1700000000 1700000060 ACCEPT OK"


def test_parse_flow_message_v2() -> None:
    rec = parse_flow_message(_ACCEPT)
    assert rec is not None and rec.dst_port == 443 and rec.bytes_transferred == 8400


def test_parse_flow_message_accepts_explicit_field_order() -> None:
    # The fields kwarg lets callers pass a v3/v4/v5 order; here the v2 superset explicitly.
    from network_threat.tools.vpc_flow_reader import _V2_DEFAULT_FIELDS

    rec = parse_flow_message(_ACCEPT, fields=_V2_DEFAULT_FIELDS)
    assert rec is not None and rec.src_ip == "10.0.0.5" and rec.dst_port == 443


def test_parse_malformed_returns_none() -> None:
    assert parse_flow_message("garbage") is None


def test_aggregate_groups_by_connection() -> None:
    recs = [parse_flow_message(_ACCEPT), parse_flow_message(_REJECT), parse_flow_message(_OTHER)]
    recs = [r for r in recs if r is not None]
    aggs = aggregate_flows(recs)
    # (10.0.0.5→1.2.3.4:443) groups the ACCEPT+REJECT; (10.0.0.9→9.9.9.9:22) is separate.
    assert len(aggs) == 2


def test_aggregate_sums_and_counts() -> None:
    recs = [parse_flow_message(_ACCEPT), parse_flow_message(_REJECT)]
    recs = [r for r in recs if r is not None]
    [agg] = aggregate_flows(recs)
    assert isinstance(agg, FlowAggregate)
    assert agg.flow_count == 2 and agg.total_bytes == 8520 and agg.total_packets == 12
    assert agg.accepted == 1 and agg.rejected == 1


def test_aggregate_empty() -> None:
    assert aggregate_flows([]) == []


def test_aggregate_single_flow() -> None:
    rec = parse_flow_message(_OTHER)
    assert rec is not None
    [agg] = aggregate_flows([rec])
    assert agg.dst_port == 22 and agg.flow_count == 1 and agg.accepted == 1
