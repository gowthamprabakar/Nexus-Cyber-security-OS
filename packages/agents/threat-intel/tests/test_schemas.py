"""Schemas tests — Task 2.

Verifies the D.4 schema re-export (Q1 substrate) plus the D.8-specific
additions (``THREAT_INTEL_FINDING_ID_RE``, ``ThreatIntelFindingType`` /
``IocType`` enums, ``ThreatIntelFinding`` wrapper, ``build_finding``
constructor, ``FindingsReport`` aggregate).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from shared.fabric.envelope import NexusEnvelope
from threat_intel.schemas import (
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    THREAT_INTEL_FINDING_ID_RE,
    AffectedResource,
    FindingsReport,
    IocType,
    Severity,
    ThreatIntelFinding,
    ThreatIntelFindingType,
    build_finding,
    severity_from_id,
    severity_to_id,
    source_token,
)

# ---------------------------------------------------------------------------
# D.4 substrate re-export — Q1
# ---------------------------------------------------------------------------


def test_ocsf_constants_are_d4_detection_finding() -> None:
    """D.8 emits identical wire shape to D.4 — class_uid 2004."""
    assert OCSF_VERSION == "1.3.0"
    assert OCSF_CATEGORY_UID == 2
    assert OCSF_CATEGORY_NAME == "Findings"
    assert OCSF_CLASS_UID == 2004
    assert OCSF_CLASS_NAME == "Detection Finding"


def test_severity_enum_round_trips_via_ocsf_id() -> None:
    for s in Severity:
        assert severity_from_id(severity_to_id(s)) is s


# ---------------------------------------------------------------------------
# FINDING_ID_RE — D.8-specific shape
# ---------------------------------------------------------------------------


def test_finding_id_re_pattern() -> None:
    assert THREAT_INTEL_FINDING_ID_RE.pattern == (
        r"^TI-(CVE_KEV|IOC_NET|IOC_RUN|TECHNIQUE)-[A-Z0-9_.]+-\d{3}-[a-z0-9_.-]+$"
    )


@pytest.mark.parametrize(
    "uid",
    [
        "TI-CVE_KEV-CVE_2024_12345-001-log4j-rce",
        "TI-IOC_NET-IPV4-042-1.2.3.4",
        "TI-IOC_RUN-FILE_SHA256-007-mimikatz-hash",
        "TI-TECHNIQUE-T1059.003-013-windows-cmd",
    ],
)
def test_finding_id_re_accepts_valid_examples(uid: str) -> None:
    assert THREAT_INTEL_FINDING_ID_RE.match(uid)


@pytest.mark.parametrize(
    "uid",
    [
        "NETWORK-PORT_SCAN-X-001-host",  # D.4-shape, not D.8
        "TI-OTHER-X-001-foo",  # invalid finding-type token
        "TI-CVE_KEV-X-foo-bar",  # missing 3-digit sequence
        "TI-CVE_KEV-X-001-FOO",  # context must be lowercase
        "ti-cve_kev-x-001-foo",  # prefix must be uppercase
    ],
)
def test_finding_id_re_rejects_invalid_examples(uid: str) -> None:
    assert not THREAT_INTEL_FINDING_ID_RE.match(uid)


# ---------------------------------------------------------------------------
# ThreatIntelFindingType — discriminator
# ---------------------------------------------------------------------------


def test_threat_intel_finding_type_has_4_values() -> None:
    """One value per correlator output (Tasks 7, 8, 9 + technique observation)."""
    members = set(ThreatIntelFindingType)
    assert len(members) == 4


def test_threat_intel_finding_type_wire_strings_have_namespace_prefix() -> None:
    """Wire strings must be prefixed with ``threat_intel_`` so D.7 / Meta-Harness
    can disambiguate from D.4 network-threat findings on the same OCSF
    class_uid 2004.
    """
    for ft in ThreatIntelFindingType:
        assert ft.value.startswith("threat_intel_"), (
            f"{ft.name}={ft.value!r} missing threat_intel_ prefix"
        )


def test_threat_intel_finding_type_wire_strings_are_stable() -> None:
    """Verbatim wire-format strings. **Renaming requires a coordinated OCSF
    wire-shape change** (per ADR-010 §"When this template stops applying").
    """
    assert ThreatIntelFindingType.CVE_IN_KEV_CATALOG.value == "threat_intel_cve_in_kev_catalog"
    assert ThreatIntelFindingType.IOC_MATCH_NETWORK.value == "threat_intel_ioc_match_network"
    assert ThreatIntelFindingType.IOC_MATCH_RUNTIME.value == "threat_intel_ioc_match_runtime"
    assert (
        ThreatIntelFindingType.ATTACK_TECHNIQUE_OBSERVED.value
        == "threat_intel_attack_technique_observed"
    )


# ---------------------------------------------------------------------------
# IocType
# ---------------------------------------------------------------------------


def test_ioc_type_has_5_values() -> None:
    members = set(IocType)
    assert len(members) == 5


def test_ioc_type_wire_strings_are_stable() -> None:
    assert IocType.IP.value == "ip"
    assert IocType.DOMAIN.value == "domain"
    assert IocType.URL.value == "url"
    assert IocType.FILE_HASH.value == "file_hash"
    assert IocType.CVE_ID.value == "cve_id"


# ---------------------------------------------------------------------------
# source_token helper
# ---------------------------------------------------------------------------


def test_source_token_for_each_finding_type() -> None:
    """All 4 source tokens map to FINDING_ID_RE-safe values."""
    assert source_token(ThreatIntelFindingType.CVE_IN_KEV_CATALOG) == "CVE_KEV"
    assert source_token(ThreatIntelFindingType.IOC_MATCH_NETWORK) == "IOC_NET"
    assert source_token(ThreatIntelFindingType.IOC_MATCH_RUNTIME) == "IOC_RUN"
    assert source_token(ThreatIntelFindingType.ATTACK_TECHNIQUE_OBSERVED) == "TECHNIQUE"


def test_source_token_round_trip_into_finding_id() -> None:
    """A finding_id built with each source token must satisfy FINDING_ID_RE."""
    for ft in ThreatIntelFindingType:
        token = source_token(ft)
        finding_id = f"TI-{token}-EXAMPLE-001-example-context"
        assert THREAT_INTEL_FINDING_ID_RE.match(finding_id), (
            f"finding_id {finding_id!r} does not match"
        )


# ---------------------------------------------------------------------------
# build_finding — happy path + validation
# ---------------------------------------------------------------------------


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
            cloud="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="workload",
            resource_id="i-0abc",
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
        )
    ]


def test_build_finding_returns_wrapper() -> None:
    finding = build_finding(
        finding_id="TI-CVE_KEV-CVE_2024_12345-001-log4j",
        finding_type=ThreatIntelFindingType.CVE_IN_KEV_CATALOG,
        severity=Severity.CRITICAL,
        title="CVE-2024-12345 observed in KEV catalog",
        description="Critical CVE actively exploited per CISA KEV.",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC),
        envelope=_envelope(),
        evidence={"cve_id": "CVE-2024-12345", "kev_listed": True},
    )
    assert isinstance(finding, ThreatIntelFinding)
    assert finding.severity == Severity.CRITICAL
    assert finding.finding_id == "TI-CVE_KEV-CVE_2024_12345-001-log4j"
    assert finding.rule_id == "threat_intel_cve_in_kev_catalog"


def test_build_finding_emits_correct_ocsf_class() -> None:
    finding = build_finding(
        finding_id="TI-IOC_NET-IPV4-001-malicious-ip",
        finding_type=ThreatIntelFindingType.IOC_MATCH_NETWORK,
        severity=Severity.HIGH,
        title="Known-bad IP observed",
        description="IOC match against bundled feed.",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC),
        envelope=_envelope(),
    )
    payload = finding.to_dict()
    assert payload["class_uid"] == 2004
    assert payload["class_name"] == "Detection Finding"
    assert payload["finding_info"]["types"] == ["threat_intel_ioc_match_network"]


def test_build_finding_rejects_bad_finding_id() -> None:
    with pytest.raises(ValueError, match="finding_id must match"):
        build_finding(
            finding_id="NETWORK-PORT_SCAN-X-001-bad",  # D.4-shape, not D.8
            finding_type=ThreatIntelFindingType.CVE_IN_KEV_CATALOG,
            severity=Severity.HIGH,
            title="x",
            description="x",
            affected=_affected(),
            detected_at=datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC),
            envelope=_envelope(),
        )


def test_build_finding_rejects_empty_affected() -> None:
    with pytest.raises(ValueError, match="affected resources"):
        build_finding(
            finding_id="TI-CVE_KEV-X-001-foo",
            finding_type=ThreatIntelFindingType.CVE_IN_KEV_CATALOG,
            severity=Severity.HIGH,
            title="x",
            description="x",
            affected=[],
            detected_at=datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC),
            envelope=_envelope(),
        )


def test_build_finding_evidence_optional() -> None:
    finding = build_finding(
        finding_id="TI-TECHNIQUE-T1059-001-windows-cmd",
        finding_type=ThreatIntelFindingType.ATTACK_TECHNIQUE_OBSERVED,
        severity=Severity.MEDIUM,
        title="ATT&CK T1059 observed",
        description="Command-line interpreter execution.",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC),
        envelope=_envelope(),
        # evidence omitted
    )
    payload = finding.to_dict()
    assert payload["evidences"] == []


# ---------------------------------------------------------------------------
# ThreatIntelFinding wrapper validation
# ---------------------------------------------------------------------------


def test_wrapper_rejects_wrong_class_uid() -> None:
    """Construction from a payload with class_uid != 2004 raises."""
    payload = {
        "class_uid": 2003,
        "finding_info": {"uid": "TI-CVE_KEV-X-001-foo"},
        "nexus_envelope": {},
    }
    with pytest.raises(ValueError, match="expected OCSF class_uid=2004"):
        ThreatIntelFinding(payload)


def test_wrapper_rejects_missing_envelope() -> None:
    payload = {
        "class_uid": 2004,
        "finding_info": {"uid": "TI-CVE_KEV-X-001-foo"},
        # nexus_envelope intentionally absent
    }
    with pytest.raises((ValueError, KeyError)):
        ThreatIntelFinding(payload)


# ---------------------------------------------------------------------------
# FindingsReport aggregate
# ---------------------------------------------------------------------------


def test_findings_report_round_trip() -> None:
    report = FindingsReport(
        agent="threat_intel",
        agent_version="0.1.0",
        customer_id="acme",
        run_id="01J0000000000000000000DSEC",
        scan_started_at=datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, 12, 0, 1, tzinfo=UTC),
    )
    assert report.total == 0

    finding = build_finding(
        finding_id="TI-CVE_KEV-X-001-foo",
        finding_type=ThreatIntelFindingType.CVE_IN_KEV_CATALOG,
        severity=Severity.CRITICAL,
        title="x",
        description="x",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC),
        envelope=_envelope(),
    )
    report.add_finding(finding)
    assert report.total == 1
    assert report.count_by_severity()["critical"] == 1


def test_findings_report_count_by_severity_zero_when_empty() -> None:
    report = FindingsReport(
        agent="threat_intel",
        agent_version="0.1.0",
        customer_id="acme",
        run_id="01J0000000000000000000DSEC",
        scan_started_at=datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, 12, 0, 1, tzinfo=UTC),
    )
    counts = report.count_by_severity()
    for sev in ("critical", "high", "medium", "low", "info"):
        assert counts[sev] == 0


# ---------------------------------------------------------------------------
# AffectedResource re-export — substrate sanity
# ---------------------------------------------------------------------------


def test_affected_resource_re_exported_from_cloud_posture() -> None:
    """AffectedResource is re-exported from F.3 cloud-posture verbatim."""
    r = AffectedResource(
        cloud="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="workload",
        resource_id="i-0abc",
        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
    )
    payload = r.to_ocsf()
    assert payload["type"] == "workload"
    assert payload["uid"] == "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc"
