"""Tests for `network_threat.schemas` — OCSF Detection Finding (class_uid 2004) typing layer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from network_threat.schemas import (
    FINDING_ID_RE,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    AffectedNetwork,
    Beacon,
    Detection,
    DnsEvent,
    DnsEventKind,
    FindingsReport,
    FindingType,
    FlowRecord,
    NetworkFinding,
    Severity,
    SuricataAlert,
    SuricataAlertSeverity,
    build_finding,
    finding_type_token,
    severity_from_id,
    severity_to_id,
    short_ip_token,
)
from shared.fabric.envelope import NexusEnvelope


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="network_threat@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic-v0.1",
        charter_invocation_id="invocation_001",
    )


def _network(src: str = "10.0.1.42", dst: str = "203.0.113.5") -> AffectedNetwork:
    return AffectedNetwork(
        src_ip=src,
        dst_ip=dst,
        src_cidr="10.0.1.0/24",
        src_port=12345,
        dst_port=443,
        vpc_id="vpc-abc123",
        account_id="123456789012",
    )


# ---------------------------- OCSF constants -----------------------------


def test_ocsf_class_constants_are_2004_detection() -> None:
    assert OCSF_CLASS_UID == 2004
    assert OCSF_CLASS_NAME == "Detection Finding"
    assert OCSF_CATEGORY_UID == 2


# ---------------------------- Severity round-trip ------------------------


@pytest.mark.parametrize(
    ("sev", "sid"),
    [
        (Severity.INFO, 1),
        (Severity.LOW, 2),
        (Severity.MEDIUM, 3),
        (Severity.HIGH, 4),
        (Severity.CRITICAL, 5),
    ],
)
def test_severity_round_trip(sev: Severity, sid: int) -> None:
    assert severity_to_id(sev) == sid
    assert severity_from_id(sid) == sev


def test_severity_6_collapses_to_critical() -> None:
    """OCSF Fatal (6) collapses to critical so downstream filters see one canonical top tier."""
    assert severity_from_id(6) == Severity.CRITICAL


def test_severity_from_id_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        severity_from_id(99)


# ---------------------------- FindingType + token map --------------------


def test_finding_type_enum_values() -> None:
    assert FindingType.PORT_SCAN.value == "network_port_scan"
    assert FindingType.BEACON.value == "network_beacon"
    assert FindingType.DGA.value == "network_dga"
    assert FindingType.SURICATA.value == "network_suricata"


@pytest.mark.parametrize(
    ("ft", "token"),
    [
        (FindingType.PORT_SCAN, "PORT_SCAN"),
        (FindingType.BEACON, "BEACON"),
        (FindingType.DGA, "DGA"),
        (FindingType.SURICATA, "SURICATA"),
    ],
)
def test_finding_type_token(ft: FindingType, token: str) -> None:
    assert finding_type_token(ft) == token


# ---------------------------- FINDING_ID_RE ------------------------------


@pytest.mark.parametrize(
    "fid",
    [
        "NETWORK-PORT_SCAN-100142-001-baseline-scan",
        "NETWORK-BEACON-100142-002-c2-7s-period",
        "NETWORK-DGA-100142-003-malicious_xyz.tld",
        "NETWORK-SURICATA-100142-004-et-malware-trojan",
    ],
)
def test_finding_id_regex_accepts_valid(fid: str) -> None:
    assert FINDING_ID_RE.match(fid) is not None


@pytest.mark.parametrize(
    "fid",
    [
        "NETWORK-PORTSCAN-100142-001-x",  # missing underscore in PORT_SCAN
        "NETWORK-port_scan-100142-001-x",  # lowercase token
        "RUNTIME-PORT_SCAN-100142-001-x",  # wrong agent prefix
        "NETWORK-PORT_SCAN-100142-1-x",  # NNN must be 3 digits
        "NETWORK-PORT_SCAN-100142-001-",  # empty context
    ],
)
def test_finding_id_regex_rejects_invalid(fid: str) -> None:
    assert FINDING_ID_RE.match(fid) is None


# ---------------------------- short_ip_token -----------------------------


def test_short_ip_token_ipv4() -> None:
    assert short_ip_token("10.0.1.42") == "100142"


def test_short_ip_token_ipv6() -> None:
    # IPv6 strips colons; chars > 12 truncated
    assert short_ip_token("2001:0db8:85a3::8a2e:0370:7334") == "20010DB885A3"


def test_short_ip_token_empty() -> None:
    assert short_ip_token("") == "UNKNOWN"
    assert short_ip_token("---") == "UNKNOWN"


# ---------------------------- FlowRecord ---------------------------------


def test_flow_record_minimal() -> None:
    fr = FlowRecord(
        src_ip="10.0.1.42",
        dst_ip="203.0.113.5",
        src_port=12345,
        dst_port=443,
        protocol=6,
        bytes_transferred=8192,
        packets=15,
        start_time=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        end_time=datetime(2026, 5, 13, 12, 1, 0, tzinfo=UTC),
        action="ACCEPT",
    )
    assert fr.duration_seconds == 60.0
    assert fr.action == "ACCEPT"


def test_flow_record_action_pattern_enforced() -> None:
    with pytest.raises(ValueError):
        FlowRecord(
            src_ip="10.0.1.42",
            dst_ip="203.0.113.5",
            src_port=12345,
            dst_port=443,
            protocol=6,
            bytes_transferred=8192,
            packets=15,
            start_time=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
            end_time=datetime(2026, 5, 13, 12, 1, 0, tzinfo=UTC),
            action="ALLOW",  # invalid — must be ACCEPT/REJECT/NODATA/SKIPDATA
        )


def test_flow_record_port_range_enforced() -> None:
    with pytest.raises(ValueError):
        FlowRecord(
            src_ip="10.0.1.42",
            dst_ip="203.0.113.5",
            src_port=12345,
            dst_port=99999,  # out of range
            protocol=6,
            bytes_transferred=0,
            packets=0,
            start_time=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
            end_time=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
            action="ACCEPT",
        )


# ---------------------------- DnsEvent -----------------------------------


def test_dns_event_query() -> None:
    e = DnsEvent(
        timestamp=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        kind=DnsEventKind.QUERY,
        query_name="malicious.xyz",
        src_ip="10.0.1.42",
    )
    assert e.kind == DnsEventKind.QUERY
    assert e.query_type == "A"  # default
    assert e.rcode == "NOERROR"  # default
    assert e.answers == ()


def test_dns_event_response_with_answers() -> None:
    e = DnsEvent(
        timestamp=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        kind=DnsEventKind.RESPONSE,
        query_name="example.com",
        query_type="A",
        answers=("93.184.216.34",),
    )
    assert e.kind == DnsEventKind.RESPONSE
    assert e.answers == ("93.184.216.34",)


# ---------------------------- SuricataAlert ------------------------------


def test_suricata_alert_minimal() -> None:
    a = SuricataAlert(
        timestamp=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        src_ip="10.0.1.42",
        dst_ip="203.0.113.5",
        src_port=12345,
        dst_port=443,
        protocol="TCP",
        signature_id=2001234,
        signature="ET MALWARE Suspicious TLS",
        severity=SuricataAlertSeverity.HIGH,
    )
    assert a.severity == SuricataAlertSeverity.HIGH
    assert a.rev == 1


# ---------------------------- Beacon -------------------------------------


def test_beacon_requires_two_or_more_connections() -> None:
    with pytest.raises(ValueError):
        Beacon(
            src_ip="10.0.1.42",
            dst_ip="203.0.113.5",
            dst_port=443,
            connection_count=1,  # below minimum
            period_seconds=60.0,
            variance_seconds=0.5,
            confidence=0.9,
            first_seen=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
            last_seen=datetime(2026, 5, 13, 12, 5, 0, tzinfo=UTC),
        )


def test_beacon_confidence_bounded() -> None:
    with pytest.raises(ValueError):
        Beacon(
            src_ip="10.0.1.42",
            dst_ip="203.0.113.5",
            dst_port=443,
            connection_count=10,
            period_seconds=60.0,
            variance_seconds=0.5,
            confidence=1.5,  # above bound
            first_seen=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
            last_seen=datetime(2026, 5, 13, 12, 10, 0, tzinfo=UTC),
        )


def test_beacon_valid() -> None:
    b = Beacon(
        src_ip="10.0.1.42",
        dst_ip="203.0.113.5",
        dst_port=443,
        connection_count=10,
        period_seconds=60.0,
        variance_seconds=0.5,
        confidence=0.92,
        first_seen=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        last_seen=datetime(2026, 5, 13, 12, 10, 0, tzinfo=UTC),
    )
    assert b.connection_count == 10
    assert b.confidence == 0.92


# ---------------------------- Detection.dedup_key ------------------------


def test_detection_dedup_key_groups_by_5min_bucket() -> None:
    """Per Q6 of the plan: composite key (type, src_cidr_or_ip, dst, 5min_bucket)."""
    base = Detection(
        finding_type=FindingType.BEACON,
        severity=Severity.HIGH,
        title="C2 beacon detected",
        description="Periodic connections to known-bad IP",
        detector_id="beacon@0.1.0",
        src_ip="10.0.1.42",
        dst_ip="203.0.113.5",
        src_cidr="10.0.1.0/24",
        detected_at=datetime(2026, 5, 13, 12, 0, 30, tzinfo=UTC),
    )
    same_bucket = base.model_copy(
        update={"detected_at": datetime(2026, 5, 13, 12, 4, 0, tzinfo=UTC)}
    )
    diff_bucket = base.model_copy(
        update={"detected_at": datetime(2026, 5, 13, 12, 5, 0, tzinfo=UTC)}
    )
    assert base.dedup_key() == same_bucket.dedup_key()
    assert base.dedup_key() != diff_bucket.dedup_key()


def test_detection_dedup_key_falls_back_to_src_ip_when_no_cidr() -> None:
    d = Detection(
        finding_type=FindingType.PORT_SCAN,
        severity=Severity.MEDIUM,
        title="Port scan from 10.0.1.42",
        description="50 distinct dst-ports in 60s",
        detector_id="port_scan@0.1.0",
        src_ip="10.0.1.42",
        src_cidr="",  # no CIDR
        detected_at=datetime(2026, 5, 13, 12, 0, 30, tzinfo=UTC),
    )
    key = d.dedup_key()
    assert key[1] == "10.0.1.42"


# ---------------------------- AffectedNetwork.to_ocsf --------------------


def test_affected_network_to_ocsf_minimal() -> None:
    n = AffectedNetwork(src_ip="10.0.1.42")
    out = n.to_ocsf()
    assert out == {"ip": "10.0.1.42"}


def test_affected_network_to_ocsf_full() -> None:
    out = _network().to_ocsf()
    assert out["ip"] == "10.0.1.42"
    assert out["traffic"]["dst_ip"] == "203.0.113.5"
    assert out["traffic"]["dst_port"] == 443
    assert out["subnet_uid"] == "10.0.1.0/24"
    assert out["port"] == 12345
    assert out["vpc_uid"] == "vpc-abc123"
    assert out["account_uid"] == "123456789012"


# ---------------------------- build_finding ------------------------------


def _evidence() -> dict[str, Any]:
    return {
        "src_ip": "10.0.1.42",
        "distinct_ports": 75,
        "window_seconds": 60,
        "ports_sampled": [22, 80, 443, 3306, 5432],
    }


def test_build_finding_happy_path_port_scan() -> None:
    f = build_finding(
        finding_id="NETWORK-PORT_SCAN-100142-001-baseline-scan",
        finding_type=FindingType.PORT_SCAN,
        severity=Severity.HIGH,
        title="Port scan from 10.0.1.42 — 75 distinct ports in 60s",
        description="Connection-rate heuristic threshold exceeded.",
        affected_networks=[_network()],
        evidence=_evidence(),
        detected_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        envelope=_envelope(),
        detector_id="port_scan@0.1.0",
    )
    assert f.severity == Severity.HIGH
    assert f.finding_type == FindingType.PORT_SCAN
    assert f.finding_id == "NETWORK-PORT_SCAN-100142-001-baseline-scan"
    assert f.detector_id == "port_scan@0.1.0"
    assert f.src_ips == ["10.0.1.42"]
    assert f.evidence["distinct_ports"] == 75


def test_build_finding_rejects_bad_finding_id() -> None:
    with pytest.raises(ValueError, match="finding_id must match"):
        build_finding(
            finding_id="BAD-FORMAT",
            finding_type=FindingType.PORT_SCAN,
            severity=Severity.HIGH,
            title="x",
            description="x",
            affected_networks=[_network()],
            evidence={},
            detected_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
            envelope=_envelope(),
            detector_id="port_scan@0.1.0",
        )


def test_build_finding_rejects_empty_affected_networks() -> None:
    with pytest.raises(ValueError, match="affected_networks list must not be empty"):
        build_finding(
            finding_id="NETWORK-PORT_SCAN-100142-001-x",
            finding_type=FindingType.PORT_SCAN,
            severity=Severity.HIGH,
            title="x",
            description="x",
            affected_networks=[],
            evidence={},
            detected_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
            envelope=_envelope(),
            detector_id="port_scan@0.1.0",
        )


# ---------------------------- NetworkFinding wrapper validation ----------


def _build_one(ft: FindingType = FindingType.BEACON) -> NetworkFinding:
    return build_finding(
        finding_id=f"NETWORK-{finding_type_token(ft)}-100142-001-test",
        finding_type=ft,
        severity=Severity.HIGH,
        title="beacon",
        description="C2 beacon",
        affected_networks=[_network()],
        evidence={"period_seconds": 60.0, "variance_seconds": 0.5, "connection_count": 10},
        detected_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        envelope=_envelope(),
        detector_id="beacon@0.1.0",
    )


def test_network_finding_rejects_wrong_class_uid() -> None:
    payload = _build_one().to_dict()
    payload["class_uid"] = 2003
    with pytest.raises(ValueError, match="expected OCSF class_uid"):
        NetworkFinding(payload)


def test_network_finding_round_trips_through_dict() -> None:
    src = _build_one()
    reload = NetworkFinding(src.to_dict())
    assert reload.finding_id == src.finding_id
    assert reload.severity == src.severity
    assert reload.evidence == src.evidence


# ---------------------------- FindingsReport -----------------------------


def test_findings_report_counts() -> None:
    rpt = FindingsReport(
        agent="network_threat",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        scan_started_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 13, 12, 0, 30, tzinfo=UTC),
    )
    rpt.add_finding(_build_one(FindingType.BEACON))
    rpt.add_finding(_build_one(FindingType.DGA))
    rpt.add_finding(_build_one(FindingType.DGA))

    assert rpt.total == 3
    sev_counts = rpt.count_by_severity()
    assert sev_counts["high"] == 3
    assert sev_counts["critical"] == 0

    ft_counts = rpt.count_by_finding_type()
    assert ft_counts["network_beacon"] == 1
    assert ft_counts["network_dga"] == 2
    assert ft_counts["network_port_scan"] == 0
    assert ft_counts["network_suricata"] == 0


def test_findings_report_count_by_finding_type_ignores_unknown() -> None:
    rpt = FindingsReport(
        agent="network_threat",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        scan_started_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 13, 12, 0, 30, tzinfo=UTC),
    )
    rpt.findings.append({"finding_info": {"types": ["unknown_type"]}, "severity_id": 4})
    counts = rpt.count_by_finding_type()
    assert all(v == 0 for v in counts.values())
