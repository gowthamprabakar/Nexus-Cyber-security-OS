"""Tests — ``threat_intel.summarizer`` (Task 11).

Verifies the deterministic markdown renderer's structure, severity
ordering, per-section composition, and -- per Q6 of the D.8 plan --
the MITRE ATT&CK CC-BY-4.0 attribution footer is always emitted
(including on empty reports).
"""

from __future__ import annotations

from datetime import UTC, datetime

from shared.fabric.envelope import NexusEnvelope
from threat_intel.schemas import (
    AffectedResource,
    FindingsReport,
    Severity,
    ThreatIntelFinding,
    ThreatIntelFindingType,
    build_finding,
)
from threat_intel.summarizer import render_summary


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d8d8",
        tenant_id="acme",
        agent_id="threat_intel",
        nlah_version="d8-v0.1",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


def _affected() -> list[AffectedResource]:
    return [
        AffectedResource(
            cloud="n/a",
            account_id="acme",
            region="n/a",
            resource_type="vulnerable_package",
            resource_id="log4j-core@2.14.0",
            arn="package:Maven:log4j-core@2.14.0",
        )
    ]


def _empty_report() -> FindingsReport:
    return FindingsReport(
        agent="threat_intel",
        agent_version="0.1.0",
        customer_id="acme",
        run_id="run_1",
        scan_started_at=datetime(2026, 5, 21, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, tzinfo=UTC),
        findings=[],
    )


def _cve_kev_finding(*, cve_id: str = "CVE-2021-44228") -> ThreatIntelFinding:
    cve_token = cve_id.replace("-", "_")
    return build_finding(
        finding_id=f"TI-CVE_KEV-{cve_token}-001-d1_vuln_aaaaaaaa",
        finding_type=ThreatIntelFindingType.CVE_IN_KEV_CATALOG,
        severity=Severity.CRITICAL,
        title=f"{cve_id} actively exploited (CISA KEV)",
        description="Log4Shell",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={
            "kev_entry": {
                "cve_id": cve_id,
                "vendor_project": "Apache",
                "product": "Log4j",
                "vulnerability_name": "Apache Log4j2 RCE",
                "date_added": "2021-12-10",
                "due_date": "2021-12-24",
                "known_ransomware_campaign_use": True,
                "required_action": "Apply updates.",
            }
        },
    )


def _ioc_net_finding(
    *,
    ip: str = "203.0.113.55",
    confidence: float = 0.9,
    severity: Severity = Severity.HIGH,
) -> ThreatIntelFinding:
    return build_finding(
        finding_id=f"TI-IOC_NET-IP_{ip}-001-d4_net_aaaaaaaa",
        finding_type=ThreatIntelFindingType.IOC_MATCH_NETWORK,
        severity=severity,
        title=f"IOC match: ip={ip}",
        description="x",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={
            "ioc_entry": {
                "ioc_type": "ip",
                "value": ip,
                "confidence": confidence,
                "source_feed": "abuse.ch",
                "first_seen": "2024-01-01T00:00:00+00:00",
                "last_seen": "2024-01-02T00:00:00+00:00",
            }
        },
    )


def _ioc_run_finding(
    *,
    sha: str = "deadbeef" * 8,
    severity: Severity = Severity.MEDIUM,
) -> ThreatIntelFinding:
    return build_finding(
        finding_id=f"TI-IOC_RUN-FILE_HASH_{sha.upper()}-001-d3_run_aaaaaaaa",
        finding_type=ThreatIntelFindingType.IOC_MATCH_RUNTIME,
        severity=severity,
        title=f"IOC match: file_hash={sha}",
        description="x",
        affected=[
            AffectedResource(
                cloud="n/a",
                account_id="acme",
                region="n/a",
                resource_type="workload_host",
                resource_id="ip-10-0-1-42",
                arn="host:ip-10-0-1-42",
            )
        ],
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={
            "ioc_entry": {
                "ioc_type": "file_hash",
                "value": sha,
                "confidence": 0.6,
                "source_feed": "abuse.ch",
                "first_seen": "2024-01-01T00:00:00+00:00",
                "last_seen": "2024-01-02T00:00:00+00:00",
            }
        },
    )


def _technique_finding() -> ThreatIntelFinding:
    return build_finding(
        finding_id="TI-TECHNIQUE-T1059-001-d3_run_aaaaaaaa",
        finding_type=ThreatIntelFindingType.ATTACK_TECHNIQUE_OBSERVED,
        severity=Severity.MEDIUM,
        title="ATT&CK T1059 observed",
        description="Command interpreter usage",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={"technique_id": "T1059"},
    )


def _report(findings: list[ThreatIntelFinding]) -> FindingsReport:
    report = _empty_report()
    for f in findings:
        report.add_finding(f)
    return report


# ---------------------------------------------------------------------------
# Empty / metadata
# ---------------------------------------------------------------------------


def test_empty_report_says_no_findings() -> None:
    md = render_summary(_empty_report())
    assert "# Threat Intel Scan" in md
    assert "Total findings: **0**" in md
    assert "No threat-intel correlations" in md


def test_empty_report_still_emits_attribution_footer() -> None:
    """Q6 license: attribution must appear even on empty reports."""
    md = render_summary(_empty_report())
    assert "MITRE ATT&CK" in md
    assert "CC-BY-4.0" in md
    assert "https://attack.mitre.org/" in md


def test_header_metadata_includes_run_id_and_customer() -> None:
    md = render_summary(_report([_cve_kev_finding()]))
    assert "Customer: `acme`" in md
    assert "Run ID: `run_1`" in md
    assert "Total findings: **1**" in md


# ---------------------------------------------------------------------------
# Attribution footer (always present)
# ---------------------------------------------------------------------------


def test_attribution_footer_present_with_findings() -> None:
    md = render_summary(_report([_cve_kev_finding(), _ioc_net_finding()]))
    assert "## Attribution" in md
    assert "MITRE ATT&CK" in md
    assert "CC-BY-4.0" in md
    assert "NVD" in md
    assert "CISA KEV" in md


def test_attribution_footer_is_last_section() -> None:
    md = render_summary(_report([_cve_kev_finding()]))
    # Last "##" header in the document should be Attribution.
    last_h2 = [line for line in md.splitlines() if line.startswith("## ")][-1]
    assert last_h2 == "## Attribution"


# ---------------------------------------------------------------------------
# Severity / type breakdowns
# ---------------------------------------------------------------------------


def test_severity_breakdown_lists_all_buckets_in_order() -> None:
    md = render_summary(_report([_cve_kev_finding()]))
    assert "## Severity breakdown" in md
    idx_critical = md.index("**Critical**")
    idx_high = md.index("**High**")
    idx_medium = md.index("**Medium**")
    idx_low = md.index("**Low**")
    idx_info = md.index("**Info**")
    assert idx_critical < idx_high < idx_medium < idx_low < idx_info


def test_finding_type_breakdown_lists_all_four_types() -> None:
    md = render_summary(_report([_cve_kev_finding()]))
    assert "**threat_intel_cve_in_kev_catalog**: 1" in md
    assert "**threat_intel_ioc_match_network**: 0" in md
    assert "**threat_intel_ioc_match_runtime**: 0" in md
    assert "**threat_intel_attack_technique_observed**: 0" in md


# ---------------------------------------------------------------------------
# Per-type sections
# ---------------------------------------------------------------------------


def test_cve_kev_section_pinned_above_findings() -> None:
    md = render_summary(_report([_cve_kev_finding(), _ioc_net_finding()]))
    cve_idx = md.index("## CVE in CISA KEV")
    findings_idx = md.index("## Findings")
    assert cve_idx < findings_idx


def test_cve_kev_section_carries_vendor_product_due_date_and_ransomware() -> None:
    md = render_summary(_report([_cve_kev_finding()]))
    assert "CVE-2021-44228" in md
    assert "Apache" in md and "Log4j" in md
    assert "2021-12-24" in md
    assert "(ransomware-linked)" in md


def test_ioc_section_includes_both_network_and_runtime_matches() -> None:
    md = render_summary(_report([_ioc_net_finding(), _ioc_run_finding()]))
    assert "## IOC matches (2)" in md
    assert "(in network)" in md
    assert "(in runtime)" in md


def test_no_cve_kev_section_when_no_kev_findings() -> None:
    md = render_summary(_report([_ioc_net_finding()]))
    assert "## CVE in CISA KEV" not in md


def test_no_ioc_section_when_no_ioc_findings() -> None:
    md = render_summary(_report([_cve_kev_finding()]))
    assert "## IOC matches" not in md


# ---------------------------------------------------------------------------
# Per-severity sections
# ---------------------------------------------------------------------------


def test_per_severity_sections_only_emitted_when_non_empty() -> None:
    md = render_summary(_report([_cve_kev_finding()]))
    assert "### Critical (1)" in md
    # No HIGH/MEDIUM/LOW findings -> those sub-sections absent.
    assert "### High" not in md
    assert "### Medium" not in md
    assert "### Low" not in md


def test_per_severity_sections_in_descending_order() -> None:
    md = render_summary(_report([_cve_kev_finding(), _ioc_net_finding(severity=Severity.HIGH)]))
    idx_crit = md.index("### Critical")
    idx_high = md.index("### High")
    assert idx_crit < idx_high


def test_finding_entries_include_id_and_title() -> None:
    md = render_summary(_report([_cve_kev_finding()]))
    assert "TI-CVE_KEV-CVE_2021_44228-001-d1_vuln_aaaaaaaa" in md
    assert "actively exploited" in md


# ---------------------------------------------------------------------------
# All four finding types together
# ---------------------------------------------------------------------------


def test_renders_all_four_finding_types() -> None:
    findings = [
        _cve_kev_finding(),
        _ioc_net_finding(),
        _ioc_run_finding(),
        _technique_finding(),
    ]
    md = render_summary(_report(findings))
    assert "Total findings: **4**" in md
    assert "**threat_intel_cve_in_kev_catalog**: 1" in md
    assert "**threat_intel_ioc_match_network**: 1" in md
    assert "**threat_intel_ioc_match_runtime**: 1" in md
    assert "**threat_intel_attack_technique_observed**: 1" in md
    # All severities counted.
    assert "**Critical**: 1" in md
    assert "**High**: 1" in md
    assert "**Medium**: 2" in md  # runtime IOC + technique = MEDIUM
