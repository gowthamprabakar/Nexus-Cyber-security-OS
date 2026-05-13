"""Tests for `network_threat.summarizer` — markdown renderer with pinned sections."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from network_threat.schemas import (
    AffectedNetwork,
    FindingsReport,
    FindingType,
    Severity,
    build_finding,
    finding_type_token,
)
from network_threat.summarizer import render_summary
from shared.fabric.envelope import NexusEnvelope


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="network_threat@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def _network(src: str = "10.0.0.5", dst: str = "203.0.113.5") -> AffectedNetwork:
    return AffectedNetwork(src_ip=src, dst_ip=dst, src_cidr="10.0.0.0/24")


def _build_one(
    *,
    ft: FindingType,
    severity: Severity = Severity.MEDIUM,
    finding_id: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> Any:
    fid = finding_id or f"NETWORK-{finding_type_token(ft)}-100005-001-test"
    return build_finding(
        finding_id=fid,
        finding_type=ft,
        severity=severity,
        title=f"{ft.value} finding",
        description="x",
        affected_networks=[_network()],
        evidence=evidence or {"src_ip": "10.0.0.5"},
        detected_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        envelope=_envelope(),
        detector_id=f"{ft.value}@0.1.0",
    )


def _empty_report() -> FindingsReport:
    return FindingsReport(
        agent="network_threat",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        scan_started_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 13, 12, 5, 0, tzinfo=UTC),
    )


def _report_with(*findings: Any) -> FindingsReport:
    rpt = _empty_report()
    for f in findings:
        rpt.add_finding(f)
    return rpt


# ---------------------------- empty report -------------------------------


def test_empty_report_renders_no_threats_message() -> None:
    md = render_summary(_empty_report())
    assert "# Network Threat Scan" in md
    assert "No network threats detected" in md
    # Severity + finding-type breakdowns are SKIPPED when empty.
    assert "Severity breakdown" not in md


def test_header_carries_run_metadata() -> None:
    md = render_summary(_report_with(_build_one(ft=FindingType.PORT_SCAN)))
    assert "cust_test" in md
    assert "run_001" in md
    assert "Scan window:" in md
    assert "Total findings: **1**" in md


# ---------------------------- pinned sections ----------------------------


def test_beacon_pin_present_when_beacons_exist() -> None:
    beacon = _build_one(
        ft=FindingType.BEACON,
        severity=Severity.HIGH,
        finding_id="NETWORK-BEACON-100005-001-periodic",
        evidence={
            "dst_ip": "1.2.3.4",
            "dst_port": 443,
            "connection_count": 20,
            "coefficient_of_variation": 0.05,
            "src_ip": "10.0.0.5",
        },
    )
    md = render_summary(_report_with(beacon))
    # Pin section above per-severity.
    pin_idx = md.find("## Beacon alerts")
    findings_idx = md.find("## Findings")
    assert pin_idx > 0
    assert findings_idx > pin_idx
    # Beacon details rendered.
    assert "1.2.3.4:443" in md
    assert "20 hits" in md
    assert "CoV 0.05" in md
    assert "NETWORK-BEACON-100005-001-periodic" in md


def test_dga_pin_present_when_dgas_exist() -> None:
    dga = _build_one(
        ft=FindingType.DGA,
        severity=Severity.MEDIUM,
        finding_id="NETWORK-DGA-100005-001-xkfqpzwv",
        evidence={
            "query_name": "xkfqpzwv.tld",
            "entropy": 4.2,
            "bigram_score": 0.0,
            "src_ip": "10.0.0.5",
        },
    )
    md = render_summary(_report_with(dga))
    assert "## DGA domains" in md
    assert "xkfqpzwv.tld" in md
    assert "entropy 4.2" in md


def test_pinned_sections_order_is_beacons_then_dga() -> None:
    """Beacons must come before DGA per the NLAH README's pin order."""
    beacon = _build_one(ft=FindingType.BEACON, severity=Severity.HIGH)
    dga = _build_one(ft=FindingType.DGA, severity=Severity.MEDIUM)
    md = render_summary(_report_with(beacon, dga))
    beacon_idx = md.find("## Beacon alerts")
    dga_idx = md.find("## DGA domains")
    assert beacon_idx > 0
    assert dga_idx > beacon_idx


def test_no_pin_when_no_beacons_no_dga() -> None:
    """Port-scan + Suricata only → no pinned sections (those go straight to per-severity)."""
    ps = _build_one(ft=FindingType.PORT_SCAN, severity=Severity.MEDIUM)
    su = _build_one(ft=FindingType.SURICATA, severity=Severity.LOW)
    md = render_summary(_report_with(ps, su))
    assert "## Beacon alerts" not in md
    assert "## DGA domains" not in md
    assert "## Findings" in md


# ---------------------------- severity sections --------------------------


def test_per_severity_sections_emitted_for_present_buckets() -> None:
    critical = _build_one(
        ft=FindingType.SURICATA,
        severity=Severity.CRITICAL,
        finding_id="NETWORK-SURICATA-100005-001-malware",
    )
    medium = _build_one(
        ft=FindingType.PORT_SCAN,
        severity=Severity.MEDIUM,
        finding_id="NETWORK-PORT_SCAN-100005-001-rate",
    )
    md = render_summary(_report_with(critical, medium))
    assert "### Critical (1)" in md
    assert "### Medium (1)" in md
    # High / Low / Info — no findings → no section.
    assert "### High (" not in md
    assert "### Low (" not in md


def test_severity_sections_ordered_critical_to_info() -> None:
    a = _build_one(ft=FindingType.SURICATA, severity=Severity.CRITICAL)
    b = _build_one(
        ft=FindingType.SURICATA,
        severity=Severity.MEDIUM,
        finding_id="NETWORK-SURICATA-100005-002-m",
    )
    md = render_summary(_report_with(a, b))
    crit_idx = md.find("### Critical")
    med_idx = md.find("### Medium")
    assert crit_idx > 0 and med_idx > crit_idx


# ---------------------------- breakdowns ---------------------------------


def test_severity_breakdown_counts_all_levels() -> None:
    findings = [
        _build_one(ft=FindingType.PORT_SCAN, severity=Severity.MEDIUM),
        _build_one(
            ft=FindingType.PORT_SCAN,
            severity=Severity.MEDIUM,
            finding_id="NETWORK-PORT_SCAN-100005-002-x",
        ),
        _build_one(
            ft=FindingType.SURICATA,
            severity=Severity.CRITICAL,
            finding_id="NETWORK-SURICATA-100005-001-malware",
        ),
    ]
    md = render_summary(_report_with(*findings))
    assert "**Critical**: 1" in md
    assert "**Medium**: 2" in md
    assert "**High**: 0" in md


def test_finding_type_breakdown_lists_all_four() -> None:
    md = render_summary(_report_with(_build_one(ft=FindingType.BEACON)))
    assert "**network_port_scan**: 0" in md
    assert "**network_beacon**: 1" in md
    assert "**network_dga**: 0" in md
    assert "**network_suricata**: 0" in md


# ---------------------------- comprehensive end-to-end -------------------


def test_comprehensive_report_renders_all_sections() -> None:
    findings = [
        _build_one(
            ft=FindingType.BEACON,
            severity=Severity.CRITICAL,
            finding_id="NETWORK-BEACON-100005-001-periodic",
            evidence={
                "dst_ip": "185.220.101.42",
                "dst_port": 443,
                "connection_count": 60,
                "coefficient_of_variation": 0.007,
                "src_ip": "10.0.0.5",
            },
        ),
        _build_one(
            ft=FindingType.DGA,
            severity=Severity.HIGH,
            finding_id="NETWORK-DGA-100005-001-rand",
            evidence={
                "query_name": "xkfqpzwvxghmpls.tld",
                "entropy": 4.21,
                "bigram_score": 0.0,
                "src_ip": "10.0.0.5",
            },
        ),
        _build_one(
            ft=FindingType.PORT_SCAN,
            severity=Severity.MEDIUM,
            finding_id="NETWORK-PORT_SCAN-100005-001-rate",
        ),
        _build_one(
            ft=FindingType.SURICATA,
            severity=Severity.LOW,
            finding_id="NETWORK-SURICATA-100005-001-info",
        ),
    ]
    md = render_summary(_report_with(*findings))
    # All sections present.
    for header in [
        "# Network Threat Scan",
        "## Severity breakdown",
        "## Finding-type breakdown",
        "## Beacon alerts",
        "## DGA domains",
        "## Findings",
        "### Critical",
        "### High",
        "### Medium",
        "### Low",
    ]:
        assert header in md
