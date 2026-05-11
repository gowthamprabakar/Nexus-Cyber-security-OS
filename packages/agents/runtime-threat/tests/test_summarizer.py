"""Tests for `runtime_threat.summarizer.render_summary`."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from runtime_threat.schemas import (
    AffectedHost,
    FindingsReport,
    FindingType,
    RuntimeFinding,
    Severity,
    build_finding,
)
from runtime_threat.summarizer import render_summary
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 11, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="runtime_threat@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic-v0.1",
        charter_invocation_id="invocation_001",
    )


def _host(host_id: str = "abc123def456") -> AffectedHost:
    return AffectedHost(hostname="ip-10-0-1-42", host_id=host_id, image_ref="nginx:1.27")


def _empty_report() -> FindingsReport:
    return FindingsReport(
        agent="runtime_threat",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_xyz",
        scan_started_at=NOW,
        scan_completed_at=NOW,
        findings=[],
    )


def _make_finding(
    *,
    finding_id: str,
    finding_type: FindingType,
    severity: Severity,
    host: AffectedHost | None = None,
    title: str = "Test runtime finding",
    evidence: dict[str, Any] | None = None,
) -> RuntimeFinding:
    return build_finding(
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        title=title,
        description="test",
        affected_hosts=[host or _host()],
        evidence=evidence if evidence is not None else {"k": "v"},
        detected_at=NOW,
        envelope=_envelope(),
    )


def _report_with(findings: list[RuntimeFinding]) -> FindingsReport:
    report = _empty_report()
    for f in findings:
        report.add_finding(f)
    return report


# ---------------------------- empty path ---------------------------------


def test_empty_report_returns_clean_summary() -> None:
    out = render_summary(_empty_report())
    assert "# Runtime Threat Scan" in out
    assert "Total findings: **0**" in out
    assert "No runtime threats detected" in out


def test_metadata_block_emitted() -> None:
    out = render_summary(_empty_report())
    assert "Customer: `cust_test`" in out
    assert "Run ID: `run_xyz`" in out


# ---------------------------- critical-alert pin -------------------------


def test_critical_severity_finding_appears_in_pinned_section() -> None:
    finding = _make_finding(
        finding_id="RUNTIME-FILE-ABC123-001-shadow_read",
        finding_type=FindingType.FILE,
        severity=Severity.CRITICAL,
    )
    out = render_summary(_report_with([finding]))
    assert "Critical runtime alerts (1)" in out
    assert "RUNTIME-FILE-ABC123-001-shadow_read" in out


def test_non_critical_finding_does_not_create_pinned_section() -> None:
    finding = _make_finding(
        finding_id="RUNTIME-PROCESS-ABC123-001-shell",
        finding_type=FindingType.PROCESS,
        severity=Severity.HIGH,
    )
    out = render_summary(_report_with([finding]))
    assert "Critical runtime alerts" not in out
    # But the finding itself still appears in the per-severity section.
    assert "RUNTIME-PROCESS-ABC123-001-shell" in out


def test_pinned_section_lists_only_critical_findings() -> None:
    crit = _make_finding(
        finding_id="RUNTIME-FILE-A-001-x",
        finding_type=FindingType.FILE,
        severity=Severity.CRITICAL,
    )
    high = _make_finding(
        finding_id="RUNTIME-PROCESS-B-001-y",
        finding_type=FindingType.PROCESS,
        severity=Severity.HIGH,
        host=_host("bbbbbbbbbbbb"),
    )
    out = render_summary(_report_with([crit, high]))
    pinned_block = out.split("Critical runtime alerts")[1].split("## Findings")[0]
    assert "RUNTIME-FILE-A-001-x" in pinned_block
    assert "RUNTIME-PROCESS-B-001-y" not in pinned_block


# ---------------------------- per-finding-type cases ---------------------


@pytest.mark.parametrize(
    "finding_type",
    [
        FindingType.PROCESS,
        FindingType.FILE,
        FindingType.NETWORK,
        FindingType.SYSCALL,
        FindingType.OSQUERY,
    ],
)
def test_each_finding_type_renders(finding_type: FindingType) -> None:
    type_token = {
        FindingType.PROCESS: "PROCESS",
        FindingType.FILE: "FILE",
        FindingType.NETWORK: "NETWORK",
        FindingType.SYSCALL: "SYSCALL",
        FindingType.OSQUERY: "OSQUERY",
    }[finding_type]
    f = _make_finding(
        finding_id=f"RUNTIME-{type_token}-ABC-001-evidence",
        finding_type=finding_type,
        severity=Severity.HIGH,
    )
    out = render_summary(_report_with([f]))
    assert finding_type.value in out


# ---------------------------- ordering -----------------------------------


def test_severity_order_is_critical_first() -> None:
    findings = [
        _make_finding(
            finding_id="RUNTIME-PROCESS-A-001-low",
            finding_type=FindingType.PROCESS,
            severity=Severity.LOW,
        ),
        _make_finding(
            finding_id="RUNTIME-FILE-B-001-crit",
            finding_type=FindingType.FILE,
            severity=Severity.CRITICAL,
            host=_host("bbbbbbbbbbbb"),
        ),
        _make_finding(
            finding_id="RUNTIME-NETWORK-C-001-high",
            finding_type=FindingType.NETWORK,
            severity=Severity.HIGH,
            host=_host("cccccccccccc"),
        ),
    ]
    out = render_summary(_report_with(findings))
    crit_pos = out.index("### Critical")
    high_pos = out.index("### High")
    low_pos = out.index("### Low")
    assert crit_pos < high_pos < low_pos


# ---------------------------- breakdown counts ---------------------------


def test_severity_breakdown_counts_match_findings() -> None:
    findings = [
        _make_finding(
            finding_id="RUNTIME-FILE-A-001-x",
            finding_type=FindingType.FILE,
            severity=Severity.CRITICAL,
        ),
        _make_finding(
            finding_id="RUNTIME-FILE-B-002-y",
            finding_type=FindingType.FILE,
            severity=Severity.CRITICAL,
            host=_host("bbbbbbbbbbbb"),
        ),
        _make_finding(
            finding_id="RUNTIME-PROCESS-C-001-z",
            finding_type=FindingType.PROCESS,
            severity=Severity.MEDIUM,
            host=_host("cccccccccccc"),
        ),
    ]
    out = render_summary(_report_with(findings))
    assert "**Critical**: 2" in out
    assert "**Medium**: 1" in out
    assert "**High**: 0" in out


def test_finding_type_breakdown_counts_match_findings() -> None:
    findings = [
        _make_finding(
            finding_id="RUNTIME-PROCESS-A-001-x",
            finding_type=FindingType.PROCESS,
            severity=Severity.HIGH,
        ),
        _make_finding(
            finding_id="RUNTIME-PROCESS-B-002-y",
            finding_type=FindingType.PROCESS,
            severity=Severity.HIGH,
            host=_host("bbbbbbbbbbbb"),
        ),
        _make_finding(
            finding_id="RUNTIME-OSQUERY-C-001-z",
            finding_type=FindingType.OSQUERY,
            severity=Severity.MEDIUM,
            host=_host("cccccccccccc"),
        ),
    ]
    out = render_summary(_report_with(findings))
    assert "**runtime_process**: 2" in out
    assert "**runtime_osquery**: 1" in out
    assert "**runtime_network**: 0" in out


# ---------------------------- mixed rollup -------------------------------


def test_multi_finding_rollup_emits_all_families_and_severities() -> None:
    findings = [
        _make_finding(
            finding_id="RUNTIME-PROCESS-A-001-shell",
            finding_type=FindingType.PROCESS,
            severity=Severity.CRITICAL,
        ),
        _make_finding(
            finding_id="RUNTIME-NETWORK-B-001-tor",
            finding_type=FindingType.NETWORK,
            severity=Severity.HIGH,
            host=_host("bbbbbbbbbbbb"),
        ),
        _make_finding(
            finding_id="RUNTIME-OSQUERY-C-001-orphan",
            finding_type=FindingType.OSQUERY,
            severity=Severity.MEDIUM,
            host=_host("cccccccccccc"),
        ),
    ]
    out = render_summary(_report_with(findings))
    # Pinned section has only the CRITICAL finding.
    assert "Critical runtime alerts (1)" in out
    # All three appear in per-severity sections.
    assert "RUNTIME-PROCESS-A-001-shell" in out
    assert "RUNTIME-NETWORK-B-001-tor" in out
    assert "RUNTIME-OSQUERY-C-001-orphan" in out
