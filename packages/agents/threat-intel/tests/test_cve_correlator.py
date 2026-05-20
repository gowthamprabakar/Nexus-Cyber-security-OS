"""Tests — ``threat_intel.correlators.cve_correlator`` (Task 7).

Builds in-memory D.1 ``findings.json`` fixtures using D.1's own
``build_finding`` (so the wire shape is the real one), runs the
correlator, and asserts the emitted ``ThreatIntelFinding``s. Forgiving-
read posture from ``investigation.tools.related_findings`` is inherited
via the same skip-on-failure pattern.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from shared.fabric.envelope import NexusEnvelope
from threat_intel.correlators.cve_correlator import build_kev_index, correlate_cve_kev
from threat_intel.schemas import Severity, ThreatIntelFindingType
from threat_intel.tools.cisa_kev import KevEntry
from vulnerability.schemas import (
    AffectedPackage,
    VulnerabilityRecord,
)
from vulnerability.schemas import (
    Severity as VulnSeverity,
)
from vulnerability.schemas import (
    build_finding as build_vuln_finding,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _envelope(tenant: str = "acme") -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d8d8",
        tenant_id=tenant,
        agent_id="threat_intel",
        nlah_version="d8-v0.1",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


def _kev(cve_id: str = "CVE-2021-44228", *, due_date: date | None = None) -> KevEntry:
    return KevEntry(
        cve_id=cve_id,
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Apache Log4j2 Remote Code Execution Vulnerability",
        date_added=date(2021, 12, 10),
        short_description="Log4Shell",
        required_action="Apply updates per vendor instructions.",
        due_date=due_date or date(2021, 12, 24),
        known_ransomware_campaign_use=True,
        notes="",
        cwes=["CWE-20", "CWE-917"],
    )


def _d1_pkg(name: str = "log4j-core", version: str = "2.14.0") -> AffectedPackage:
    return AffectedPackage(name=name, version=version, ecosystem="Maven", package_manager="maven")


def _d1_vuln(cve_id: str = "CVE-2021-44228") -> VulnerabilityRecord:
    return VulnerabilityRecord(
        cve_id=cve_id,
        title=f"Detail for {cve_id}",
        cvss_v3_score=10.0,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        epss_probability=0.97,
        kev_flag=True,
        fix_available=True,
        fixed_version="2.16.0",
        references=(),
    )


def _write_d1_findings(workspace: Path, payloads: list[dict[str, Any]]) -> None:
    report = {
        "agent": "vulnerability",
        "agent_version": "0.1.0",
        "customer_id": "acme",
        "run_id": "run_1",
        "scan_started_at": "2026-05-21T00:00:00+00:00",
        "scan_completed_at": "2026-05-21T00:00:05+00:00",
        "findings": payloads,
    }
    (workspace / "findings.json").write_text(json.dumps(report), encoding="utf-8")


def _d1_finding_payload(
    *,
    finding_id: str = "VULN-log4j_core-CVE-2021-44228",
    cve_id: str = "CVE-2021-44228",
    pkg_name: str = "log4j-core",
    pkg_version: str = "2.14.0",
) -> dict[str, Any]:
    finding = build_vuln_finding(
        finding_id=finding_id,
        severity=VulnSeverity.CRITICAL,
        title="Apache Log4j2 RCE",
        description="Log4Shell",
        affected_packages=[_d1_pkg(pkg_name, pkg_version)],
        vulnerabilities=[_d1_vuln(cve_id)],
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    return finding.to_dict()


# ---------------------------------------------------------------------------
# build_kev_index
# ---------------------------------------------------------------------------


def test_build_kev_index_keys_by_cve_id() -> None:
    a = _kev("CVE-2021-44228")
    b = _kev("CVE-2024-12345")
    idx = build_kev_index([a, b])
    assert set(idx.keys()) == {"CVE-2021-44228", "CVE-2024-12345"}
    assert idx["CVE-2021-44228"] is a


def test_build_kev_index_handles_empty_input() -> None:
    assert build_kev_index([]) == {}


# ---------------------------------------------------------------------------
# Skip-cases (no findings emitted)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_correlate_returns_empty_when_workspace_is_none() -> None:
    findings = await correlate_cve_kev(
        vulnerability_workspace=None,
        kev_index=build_kev_index([_kev()]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_correlate_returns_empty_when_kev_index_empty(tmp_path: Path) -> None:
    _write_d1_findings(tmp_path, [_d1_finding_payload()])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index={},
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_correlate_returns_empty_when_findings_json_missing(tmp_path: Path) -> None:
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev()]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_correlate_returns_empty_when_findings_json_malformed(tmp_path: Path) -> None:
    (tmp_path / "findings.json").write_text("{not json", encoding="utf-8")
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev()]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_correlate_returns_empty_when_no_cve_matches(tmp_path: Path) -> None:
    """D.1 finding's CVE is not in the KEV index — no emission."""
    _write_d1_findings(
        tmp_path,
        [_d1_finding_payload(finding_id="VULN-pkg_a-CVE-2024-9999", cve_id="CVE-2024-9999")],
    )
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


# ---------------------------------------------------------------------------
# Happy-path emit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_correlate_emits_one_finding_per_cve_in_kev_match(tmp_path: Path) -> None:
    _write_d1_findings(tmp_path, [_d1_finding_payload()])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_emitted_finding_carries_threat_intel_discriminator(tmp_path: Path) -> None:
    _write_d1_findings(tmp_path, [_d1_finding_payload()])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    ti_finding = findings[0]
    assert ti_finding.rule_id == ThreatIntelFindingType.CVE_IN_KEV_CATALOG.value
    assert ti_finding.rule_id == "threat_intel_cve_in_kev_catalog"


@pytest.mark.asyncio
async def test_emitted_finding_severity_critical_for_kev(tmp_path: Path) -> None:
    """KEV = actively exploited per CISA -> CRITICAL."""
    _write_d1_findings(tmp_path, [_d1_finding_payload()])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_emitted_finding_id_matches_ti_regex(tmp_path: Path) -> None:
    _write_d1_findings(tmp_path, [_d1_finding_payload()])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    fid = findings[0].finding_id
    assert fid.startswith("TI-CVE_KEV-CVE_2021_44228-001-")
    assert "d1_vuln_" in fid


@pytest.mark.asyncio
async def test_emitted_finding_evidence_carries_kev_metadata(tmp_path: Path) -> None:
    _write_d1_findings(tmp_path, [_d1_finding_payload()])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    payload = findings[0].to_dict()
    evidence = payload["evidences"][0]
    assert evidence["kev_entry"]["cve_id"] == "CVE-2021-44228"
    assert evidence["kev_entry"]["vendor_project"] == "Apache"
    assert evidence["kev_entry"]["known_ransomware_campaign_use"] is True
    assert evidence["source_d1_finding_id"] == "VULN-log4j_core-CVE-2021-44228"


@pytest.mark.asyncio
async def test_emitted_finding_carries_affected_package_resource(tmp_path: Path) -> None:
    _write_d1_findings(tmp_path, [_d1_finding_payload()])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    resources = findings[0].resources
    assert len(resources) == 1
    assert resources[0]["type"] == "vulnerable_package"
    assert resources[0]["uid"] == "package:Maven:log4j-core@2.14.0"


@pytest.mark.asyncio
async def test_multiple_d1_findings_emit_per_match(tmp_path: Path) -> None:
    """Two D.1 findings both with KEV-listed CVEs -> two D.8 findings, sequence increments."""
    _write_d1_findings(
        tmp_path,
        [
            _d1_finding_payload(
                finding_id="VULN-log4j_core-CVE-2021-44228",
                cve_id="CVE-2021-44228",
                pkg_name="log4j-core",
            ),
            _d1_finding_payload(
                finding_id="VULN-spring_beans-CVE-2022-22965",
                cve_id="CVE-2022-22965",
                pkg_name="spring-beans",
                pkg_version="5.3.18",
            ),
        ],
    )
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228"), _kev("CVE-2022-22965")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 2
    seqs = [f.finding_id.split("-")[3] for f in findings]
    assert seqs == ["001", "002"]


@pytest.mark.asyncio
async def test_non_d1_class_uid_entries_skipped(tmp_path: Path) -> None:
    """A class_uid 2003 (compliance) entry in the same file is skipped."""
    d1_payload = _d1_finding_payload()
    other_payload = {**d1_payload, "class_uid": 2003}
    _write_d1_findings(tmp_path, [other_payload, d1_payload])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_malformed_d1_finding_skipped(tmp_path: Path) -> None:
    """A D.1 entry whose finding_info.uid doesn't match VULN-... regex is skipped."""
    good = _d1_finding_payload()
    bad: dict[str, Any] = {**good, "finding_info": {**good["finding_info"], "uid": "garbage-id"}}
    _write_d1_findings(tmp_path, [bad, good])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_envelope_tenant_propagates_to_resource_account_id(tmp_path: Path) -> None:
    _write_d1_findings(tmp_path, [_d1_finding_payload()])
    findings = await correlate_cve_kev(
        vulnerability_workspace=tmp_path,
        kev_index=build_kev_index([_kev("CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope("contoso"),
    )
    account_id = findings[0].resources[0]["owner"]["account_uid"]
    assert account_id == "contoso"
