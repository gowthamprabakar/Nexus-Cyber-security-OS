"""Tests for `network_threat.enrichment`."""

from __future__ import annotations

from datetime import UTC, datetime

from network_threat.enrichment import enrich_with_intel
from network_threat.schemas import Detection, FindingType, Severity


def _det(
    *,
    ft: FindingType,
    severity: Severity = Severity.MEDIUM,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "203.0.113.5",
    evidence: dict[str, object] | None = None,
) -> Detection:
    return Detection(
        finding_type=ft,
        severity=severity,
        title="x",
        description="x",
        detector_id=f"{ft.value}@0.1.0",
        src_ip=src_ip,
        dst_ip=dst_ip,
        detected_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        evidence=evidence or {},
    )


# ---------------------------- pass-through ------------------------------


def test_empty_input_returns_empty() -> None:
    assert enrich_with_intel([]) == ()


def test_no_match_returns_detection_unchanged() -> None:
    det = _det(
        ft=FindingType.BEACON,
        dst_ip="93.184.216.34",  # example.com — not on intel
        evidence={"dst_ip": "93.184.216.34"},
    )
    out = enrich_with_intel([det])
    assert len(out) == 1
    assert "intel" not in out[0].evidence
    assert out[0].severity == det.severity


# ---------------------------- DGA enrichment ----------------------------


def test_dga_dynamic_dns_suffix_matches() -> None:
    det = _det(
        ft=FindingType.DGA,
        severity=Severity.MEDIUM,
        evidence={"query_name": "xkfqpzwv.duckdns.org"},
    )
    out = enrich_with_intel([det])
    assert len(out) == 1
    intel = out[0].evidence["intel"]
    assert "dynamic_dns" in intel["tags"]
    assert "known_bad" in intel["tags"]
    assert intel["matched_domain_suffix"] == "duckdns.org"
    # Severity uplifted MEDIUM → HIGH.
    assert out[0].severity == Severity.HIGH


def test_dga_url_shortener_matches() -> None:
    det = _det(
        ft=FindingType.DGA,
        severity=Severity.MEDIUM,
        evidence={"query_name": "is.gd"},
    )
    out = enrich_with_intel([det])
    intel = out[0].evidence["intel"]
    assert "url_shortener" in intel["tags"]
    assert intel["matched_domain_suffix"] == "is.gd"


def test_dga_longest_suffix_match_preferred() -> None:
    """For overlapping suffixes (e.g. 'no-ip.com' vs 'noip.com'), pick longest."""
    det = _det(
        ft=FindingType.DGA,
        severity=Severity.MEDIUM,
        evidence={"query_name": "sub.no-ip.com"},
    )
    out = enrich_with_intel([det])
    assert out[0].evidence["intel"]["matched_domain_suffix"] == "no-ip.com"


def test_dga_no_qname_no_match() -> None:
    det = _det(ft=FindingType.DGA, evidence={})
    out = enrich_with_intel([det])
    assert "intel" not in out[0].evidence


def test_dga_partial_label_does_not_false_match() -> None:
    """'evilduckdns.org' is NOT a suffix match for 'duckdns.org' — must be preceded by '.'."""
    det = _det(
        ft=FindingType.DGA,
        evidence={"query_name": "evilduckdns.org"},
    )
    out = enrich_with_intel([det])
    assert "intel" not in out[0].evidence


# ---------------------------- BEACON enrichment -------------------------


def test_beacon_tor_exit_matches() -> None:
    det = _det(
        ft=FindingType.BEACON,
        severity=Severity.HIGH,
        dst_ip="185.220.101.42",  # in 185.220.101.0/24
        evidence={"dst_ip": "185.220.101.42"},
    )
    out = enrich_with_intel([det])
    intel = out[0].evidence["intel"]
    assert "tor_exit" in intel["tags"]
    assert "known_bad" in intel["tags"]  # 185.220.101.0/24 also in known_bad
    # HIGH → CRITICAL on uplift.
    assert out[0].severity == Severity.CRITICAL


def test_beacon_known_bad_ip_matches() -> None:
    det = _det(
        ft=FindingType.BEACON,
        severity=Severity.MEDIUM,
        dst_ip="193.218.118.99",  # in 193.218.118.0/24
        evidence={"dst_ip": "193.218.118.99"},
    )
    out = enrich_with_intel([det])
    intel = out[0].evidence["intel"]
    assert "known_bad" in intel["tags"]
    assert intel["matched_ip_cidr"] == "193.218.118.0/24"
    assert out[0].severity == Severity.HIGH


def test_beacon_dst_ip_falls_back_to_field_when_evidence_missing() -> None:
    det = _det(
        ft=FindingType.BEACON,
        dst_ip="185.220.101.42",
        evidence={},  # evidence lacks dst_ip
    )
    out = enrich_with_intel([det])
    # The annotation should still fire from det.dst_ip.
    assert "intel" in out[0].evidence


# ---------------------------- PORT_SCAN enrichment ----------------------


def test_port_scan_src_ip_tor_match() -> None:
    det = _det(
        ft=FindingType.PORT_SCAN,
        severity=Severity.MEDIUM,
        src_ip="171.25.193.42",  # in 171.25.193.0/24
        evidence={"src_ip": "171.25.193.42"},
    )
    out = enrich_with_intel([det])
    intel = out[0].evidence["intel"]
    assert "tor_exit" in intel["tags"]
    assert out[0].severity == Severity.HIGH


def test_port_scan_non_intel_ip_no_match() -> None:
    det = _det(
        ft=FindingType.PORT_SCAN,
        src_ip="8.8.8.8",  # Google DNS, not on intel
        evidence={"src_ip": "8.8.8.8"},
    )
    out = enrich_with_intel([det])
    assert "intel" not in out[0].evidence


# ---------------------------- SURICATA: no enrichment -------------------


def test_suricata_never_enriched() -> None:
    """Suricata signatures carry their own intel; double-tagging would inflate severity."""
    det = _det(
        ft=FindingType.SURICATA,
        severity=Severity.HIGH,
        src_ip="185.220.101.42",
        evidence={"signature_id": 2001234},
    )
    out = enrich_with_intel([det])
    assert "intel" not in out[0].evidence
    assert out[0].severity == Severity.HIGH


# ---------------------------- severity uplift ceiling -------------------


def test_critical_does_not_uplift_past_ceiling() -> None:
    det = _det(
        ft=FindingType.BEACON,
        severity=Severity.CRITICAL,
        dst_ip="185.220.101.42",
        evidence={"dst_ip": "185.220.101.42"},
    )
    out = enrich_with_intel([det])
    # Intel annotation present but severity capped.
    assert "intel" in out[0].evidence
    assert out[0].severity == Severity.CRITICAL


def test_low_severity_does_not_uplift() -> None:
    """LOW isn't emitted by D.4 detectors today, but the function must handle it."""
    det = _det(
        ft=FindingType.BEACON,
        severity=Severity.LOW,
        dst_ip="185.220.101.42",
        evidence={"dst_ip": "185.220.101.42"},
    )
    out = enrich_with_intel([det])
    # Intel annotation present but LOW stays LOW (uplift only for MEDIUM/HIGH).
    assert "intel" in out[0].evidence
    assert out[0].severity == Severity.LOW


# ---------------------------- malformed-ip robustness -------------------


def test_unparseable_ip_does_not_crash() -> None:
    det = _det(
        ft=FindingType.BEACON,
        dst_ip="not-an-ip",
        evidence={"dst_ip": "not-an-ip"},
    )
    out = enrich_with_intel([det])
    assert "intel" not in out[0].evidence


def test_dash_ip_skipped() -> None:
    det = _det(
        ft=FindingType.PORT_SCAN,
        src_ip="-",
        evidence={"src_ip": "-"},
    )
    out = enrich_with_intel([det])
    assert "intel" not in out[0].evidence
