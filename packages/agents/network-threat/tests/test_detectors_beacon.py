"""Tests for `network_threat.detectors.beacon`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from network_threat.detectors.beacon import (
    DEFAULT_MAX_COV,
    DEFAULT_MIN_COUNT,
    DEFAULT_MIN_PERIOD_SECONDS,
    detect_beacon,
)
from network_threat.schemas import FindingType, FlowRecord, Severity


def _flow(
    *,
    src: str = "10.0.0.5",
    dst: str = "203.0.113.5",
    dst_port: int = 443,
    start: datetime,
    duration_seconds: float = 0.5,
    action: str = "ACCEPT",
) -> FlowRecord:
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


def _periodic_flows(
    *,
    src: str = "10.0.0.5",
    dst: str = "203.0.113.5",
    dst_port: int = 443,
    count: int = 10,
    period_seconds: float = 60.0,
    jitter_seconds: float = 0.0,
    start: datetime | None = None,
) -> list[FlowRecord]:
    """Generate `count` connections at `period_seconds` ± `jitter_seconds`."""
    if start is None:
        start = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    return [
        _flow(
            src=src,
            dst=dst,
            dst_port=dst_port,
            start=start
            + timedelta(seconds=i * period_seconds + (i * jitter_seconds if i % 2 else 0)),
        )
        for i in range(count)
    ]


# ---------------------------- happy path ---------------------------------


def test_no_records_returns_empty() -> None:
    assert detect_beacon([]) == ()


def test_below_min_count_emits_nothing() -> None:
    flows = _periodic_flows(count=4)  # < default 5
    assert detect_beacon(flows) == ()


def test_perfect_periodic_emits_detection() -> None:
    flows = _periodic_flows(count=10, period_seconds=60.0)
    out = detect_beacon(flows)
    assert len(out) == 1
    det = out[0]
    assert det.finding_type == FindingType.BEACON
    assert det.src_ip == "10.0.0.5"
    assert det.dst_ip == "203.0.113.5"
    assert det.evidence["connection_count"] == 10
    # Period should be ~60s; CoV ~0 (perfectly periodic).
    assert abs(det.evidence["period_seconds"] - 60.0) < 0.01
    assert det.evidence["coefficient_of_variation"] < 0.01


def test_severity_medium_at_threshold() -> None:
    flows = _periodic_flows(count=5, period_seconds=60.0)
    out = detect_beacon(flows)
    assert out[0].severity == Severity.MEDIUM


def test_severity_high_at_count_20_low_cov() -> None:
    flows = _periodic_flows(count=20, period_seconds=60.0)
    out = detect_beacon(flows)
    assert out[0].severity == Severity.HIGH


def test_severity_critical_at_count_50_low_cov() -> None:
    flows = _periodic_flows(count=50, period_seconds=60.0)
    out = detect_beacon(flows)
    assert out[0].severity == Severity.CRITICAL


# ---------------------------- jitter filtering ---------------------------


def test_high_jitter_filtered_out() -> None:
    """Random-shape traffic (CoV > 0.30) should NOT be flagged."""
    start = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    # Make inter-arrivals wildly variable: 1s, 60s, 2s, 60s, 3s, ...
    times = [
        start,
        start + timedelta(seconds=1),
        start + timedelta(seconds=61),
        start + timedelta(seconds=63),
        start + timedelta(seconds=123),
        start + timedelta(seconds=125),
        start + timedelta(seconds=185),
    ]
    flows = [_flow(start=t) for t in times]
    assert detect_beacon(flows) == ()


def test_moderate_jitter_within_cov_threshold_flagged() -> None:
    """Small jitter (±0.5s on 60s = 0.8% CoV) is still a beacon."""
    flows = _periodic_flows(count=10, period_seconds=60.0, jitter_seconds=0.5)
    out = detect_beacon(flows)
    assert len(out) == 1
    assert out[0].evidence["coefficient_of_variation"] < 0.30


# ---------------------------- grouping -----------------------------------


def test_separate_destinations_emit_separate_detections() -> None:
    flows = _periodic_flows(dst="1.1.1.1", count=10) + _periodic_flows(dst="2.2.2.2", count=10)
    out = detect_beacon(flows)
    assert len(out) == 2
    dst_ips = {d.evidence["dst_ip"] for d in out}
    assert dst_ips == {"1.1.1.1", "2.2.2.2"}


def test_separate_ports_emit_separate_detections() -> None:
    flows = _periodic_flows(dst_port=443, count=10) + _periodic_flows(dst_port=8443, count=10)
    out = detect_beacon(flows)
    assert len(out) == 2


def test_separate_sources_share_one_detection_only_if_pair_unique() -> None:
    flows = _periodic_flows(src="10.0.0.5", count=10) + _periodic_flows(src="10.0.0.6", count=10)
    out = detect_beacon(flows)
    assert len(out) == 2


# ---------------------------- filters ------------------------------------


def test_reject_records_skipped() -> None:
    start = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    flows = [_flow(start=start + timedelta(seconds=i * 60), action="REJECT") for i in range(10)]
    assert detect_beacon(flows) == ()


def test_loopback_source_filtered() -> None:
    flows = _periodic_flows(src="127.0.0.1", count=10)
    assert detect_beacon(flows) == ()


def test_link_local_source_filtered() -> None:
    flows = _periodic_flows(src="169.254.169.254", count=10)  # AWS IMDS
    assert detect_beacon(flows) == ()


# ---------------------------- period filtering ---------------------------


def test_sub_second_period_filtered() -> None:
    """Connections 100ms apart aren't beacons; they're retransmits or storms."""
    flows = _periodic_flows(count=10, period_seconds=0.1)
    assert detect_beacon(flows) == ()


def test_custom_min_period_honored() -> None:
    flows = _periodic_flows(count=10, period_seconds=0.5)
    # With default min_period 1.0, 0.5s period filtered.
    assert detect_beacon(flows) == ()
    # Lower min_period and the same flows pass.
    out = detect_beacon(flows, min_period_seconds=0.1)
    assert len(out) == 1


# ---------------------------- validation ---------------------------------


def test_min_count_below_3_raises() -> None:
    with pytest.raises(ValueError, match="min_count must be >= 3"):
        detect_beacon([], min_count=2)


def test_max_cov_zero_raises() -> None:
    with pytest.raises(ValueError, match="max_cov must be > 0"):
        detect_beacon([], max_cov=0)


def test_min_period_negative_raises() -> None:
    with pytest.raises(ValueError, match="min_period_seconds must be > 0"):
        detect_beacon([], min_period_seconds=0)


def test_defaults_match_constants() -> None:
    assert DEFAULT_MIN_COUNT == 5
    assert DEFAULT_MAX_COV == 0.30
    assert DEFAULT_MIN_PERIOD_SECONDS == 1.0


# ---------------------------- evidence shape -----------------------------


def test_evidence_carries_all_expected_keys() -> None:
    flows = _periodic_flows(count=10, period_seconds=60.0)
    out = detect_beacon(flows)
    ev = out[0].evidence
    expected_keys = {
        "finding_id",
        "src_ip",
        "dst_ip",
        "dst_port",
        "connection_count",
        "period_seconds",
        "variance_seconds",
        "coefficient_of_variation",
        "confidence",
        "first_seen",
        "last_seen",
    }
    assert expected_keys.issubset(ev.keys())


def test_finding_id_pattern() -> None:
    flows = _periodic_flows(src="10.0.1.42", count=10)
    out = detect_beacon(flows)
    assert out[0].evidence["finding_id"] == "NETWORK-BEACON-100142-001-periodic"


def test_confidence_bounded() -> None:
    flows = _periodic_flows(count=100, period_seconds=60.0)
    out = detect_beacon(flows)
    conf = out[0].evidence["confidence"]
    assert 0.0 <= conf <= 1.0
