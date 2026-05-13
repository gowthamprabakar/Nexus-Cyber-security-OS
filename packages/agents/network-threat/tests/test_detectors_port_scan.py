"""Tests for `network_threat.detectors.port_scan`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from network_threat.detectors.port_scan import (
    DEFAULT_MIN_DISTINCT_PORTS,
    DEFAULT_WINDOW_SECONDS,
    detect_port_scan,
)
from network_threat.schemas import FindingType, FlowRecord, Severity


def _flow(
    *,
    src: str = "10.0.0.5",
    dst: str = "203.0.113.5",
    dst_port: int = 443,
    start: datetime | None = None,
    duration_seconds: float = 1.0,
    action: str = "ACCEPT",
) -> FlowRecord:
    if start is None:
        start = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    return FlowRecord(
        src_ip=src,
        dst_ip=dst,
        src_port=49152,
        dst_port=dst_port,
        protocol=6,
        bytes_transferred=100,
        packets=1,
        start_time=start,
        end_time=start + timedelta(seconds=duration_seconds),
        action=action,  # type: ignore[arg-type]
    )


def _scan_flows(
    src: str,
    n_ports: int,
    *,
    start: datetime | None = None,
    spacing_ms: int = 100,
) -> list[FlowRecord]:
    if start is None:
        start = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    return [
        _flow(
            src=src,
            dst_port=1024 + i,
            start=start + timedelta(milliseconds=i * spacing_ms),
        )
        for i in range(n_ports)
    ]


# ---------------------------- happy path ---------------------------------


def test_no_records_returns_empty_tuple() -> None:
    assert detect_port_scan([]) == ()


def test_under_threshold_emits_nothing() -> None:
    flows = _scan_flows("10.0.0.5", 49)  # below 50 default
    out = detect_port_scan(flows)
    assert out == ()


def test_at_threshold_emits_medium() -> None:
    flows = _scan_flows("10.0.0.5", 50)
    out = detect_port_scan(flows)
    assert len(out) == 1
    det = out[0]
    assert det.finding_type == FindingType.PORT_SCAN
    assert det.severity == Severity.MEDIUM
    assert det.evidence["distinct_ports"] == 50
    assert det.src_ip == "10.0.0.5"


def test_high_threshold_emits_high_severity() -> None:
    flows = _scan_flows("10.0.0.5", 150)
    out = detect_port_scan(flows)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH
    assert out[0].evidence["distinct_ports"] == 150


def test_critical_threshold_emits_critical_severity() -> None:
    flows = _scan_flows("10.0.0.5", 250)
    out = detect_port_scan(flows)
    assert len(out) == 1
    assert out[0].severity == Severity.CRITICAL


# ---------------------------- window mechanics ---------------------------


def test_widely_spaced_scans_split_across_windows() -> None:
    """If 50 ports are spaced 2s apart over 100s, none of them fall in a 60s window."""
    flows = _scan_flows("10.0.0.5", 50, spacing_ms=2000)  # 50 ports in 100s
    out = detect_port_scan(flows, window_seconds=60)
    assert out == ()


def test_two_scan_bursts_same_src_emit_two_detections() -> None:
    """Two bursts of 50 ports each, separated by 5min, emit two detections (no overlap)."""
    first = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    second = datetime(2026, 5, 13, 12, 10, 0, tzinfo=UTC)
    flows = _scan_flows("10.0.0.5", 50, start=first) + _scan_flows("10.0.0.5", 50, start=second)
    out = detect_port_scan(flows)
    assert len(out) == 2
    # finding_ids increment per-source.
    fids = sorted(d.evidence["finding_id"] for d in out)
    assert fids[0].endswith("-001-rate")
    assert fids[1].endswith("-002-rate")


def test_two_sources_each_emit_their_own_detection() -> None:
    flows = _scan_flows("10.0.0.5", 60) + _scan_flows("10.0.0.6", 60)
    out = detect_port_scan(flows)
    assert len(out) == 2
    sources = {d.src_ip for d in out}
    assert sources == {"10.0.0.5", "10.0.0.6"}


def test_overlapping_windows_dedupe_via_skip_ahead() -> None:
    """Once a window crosses the threshold, the next window starts AFTER it —
    we don't re-emit the same scan via overlapping windows."""
    flows = _scan_flows("10.0.0.5", 75)
    out = detect_port_scan(flows)
    assert len(out) == 1


# ---------------------------- filters ------------------------------------


def test_reject_records_skipped() -> None:
    flows = [_flow(src="10.0.0.5", dst_port=1024 + i, action="REJECT") for i in range(60)]
    out = detect_port_scan(flows)
    assert out == ()


def test_loopback_source_filtered() -> None:
    flows = _scan_flows("127.0.0.1", 60)
    out = detect_port_scan(flows)
    assert out == ()


def test_link_local_source_filtered() -> None:
    flows = _scan_flows("169.254.169.254", 60)  # AWS IMDS endpoint
    out = detect_port_scan(flows)
    assert out == ()


def test_unspecified_source_filtered() -> None:
    flows = _scan_flows("0.0.0.0", 60)  # noqa: S104  # string filter, not a bind address
    out = detect_port_scan(flows)
    assert out == ()


def test_unparseable_ip_not_filtered() -> None:
    """Unparseable IPs go through — operator may want to see them."""
    flows = _scan_flows("not-an-ip", 60)
    out = detect_port_scan(flows)
    assert len(out) == 1


def test_zero_dst_port_excluded_from_distinct_count() -> None:
    """dst_port=0 shows up in SKIPDATA records; doesn't count toward 'distinct ports'."""
    flows = _scan_flows("10.0.0.5", 50)
    # Add 10 zero-port flows; distinct count should still be 50.
    zeros = [
        _flow(src="10.0.0.5", dst_port=0, start=flows[0].start_time + timedelta(milliseconds=i))
        for i in range(10)
    ]
    out = detect_port_scan(flows + zeros)
    assert len(out) == 1
    assert out[0].evidence["distinct_ports"] == 50


# ---------------------------- evidence shape -----------------------------


def test_evidence_ports_sampled_capped_at_10() -> None:
    flows = _scan_flows("10.0.0.5", 100)
    out = detect_port_scan(flows)
    assert len(out) == 1
    assert len(out[0].evidence["ports_sampled"]) == 10
    # Sampled ports are sorted ascending; first 10 from 1024..1033.
    assert out[0].evidence["ports_sampled"] == list(range(1024, 1034))


def test_finding_id_pattern() -> None:
    flows = _scan_flows("10.0.1.42", 60)
    out = detect_port_scan(flows)
    assert len(out) == 1
    assert out[0].evidence["finding_id"] == "NETWORK-PORT_SCAN-100142-001-rate"


def test_evidence_window_bounds_captured() -> None:
    start = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    flows = _scan_flows("10.0.0.5", 60, start=start, spacing_ms=100)
    out = detect_port_scan(flows)
    assert len(out) == 1
    ev = out[0].evidence
    assert ev["window_start"] == start.isoformat()
    # Last port is index 59, 100ms apart → window_end at start + 5900ms.
    assert ev["window_end"] == (start + timedelta(milliseconds=5900)).isoformat()


# ---------------------------- validation ---------------------------------


def test_min_distinct_ports_zero_raises() -> None:
    with pytest.raises(ValueError, match="min_distinct_ports must be >= 1"):
        detect_port_scan([], min_distinct_ports=0)


def test_window_seconds_zero_raises() -> None:
    with pytest.raises(ValueError, match="window_seconds must be >= 1"):
        detect_port_scan([], window_seconds=0)


def test_custom_thresholds_honored() -> None:
    flows = _scan_flows("10.0.0.5", 10)
    out = detect_port_scan(flows, min_distinct_ports=10)
    assert len(out) == 1
    assert out[0].evidence["distinct_ports"] == 10


def test_default_thresholds_match_constants() -> None:
    assert DEFAULT_MIN_DISTINCT_PORTS == 50
    assert DEFAULT_WINDOW_SECONDS == 60
