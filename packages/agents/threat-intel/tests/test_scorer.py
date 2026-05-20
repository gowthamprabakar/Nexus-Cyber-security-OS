"""Tests — ``threat_intel.scorer`` (Task 10).

Validates the deterministic, table-driven severity scorer:

  - CVE_IN_KEV_CATALOG          -> CRITICAL.
  - IOC_MATCH_NETWORK / RUNTIME -> HIGH / MEDIUM / LOW by confidence
    floor (0.8 / 0.5 / below).
  - ATTACK_TECHNIQUE_OBSERVED   -> MEDIUM.

Plus the rebuild semantics: findings whose correlator-emitted severity
already matches canonical are returned as-is; mismatched findings get
re-stamped (severity_id + severity string) while the rest of the
payload, including finding_info.uid and nexus_envelope, stays
verbatim.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from shared.fabric.envelope import NexusEnvelope
from threat_intel.schemas import (
    AffectedResource,
    Severity,
    ThreatIntelFinding,
    ThreatIntelFindingType,
    build_finding,
)
from threat_intel.scorer import score_findings, score_severity


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


def _cve_kev_finding(*, severity: Severity = Severity.CRITICAL) -> ThreatIntelFinding:
    return build_finding(
        finding_id="TI-CVE_KEV-CVE_2021_44228-001-d1_vuln_aaaaaaaa",
        finding_type=ThreatIntelFindingType.CVE_IN_KEV_CATALOG,
        severity=severity,
        title="x",
        description="y",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={"kev_entry": {"cve_id": "CVE-2021-44228"}},
    )


def _ioc_net_finding(
    *,
    confidence: float,
    severity: Severity = Severity.HIGH,
) -> ThreatIntelFinding:
    return build_finding(
        finding_id="TI-IOC_NET-IP_203.0.113.55-001-d4_net_aaaaaaaa",
        finding_type=ThreatIntelFindingType.IOC_MATCH_NETWORK,
        severity=severity,
        title="x",
        description="y",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={
            "ioc_entry": {
                "ioc_type": "ip",
                "value": "203.0.113.55",
                "confidence": confidence,
                "source_feed": "abuse.ch",
                "first_seen": "2024-01-01T00:00:00+00:00",
                "last_seen": "2024-01-02T00:00:00+00:00",
            }
        },
    )


def _ioc_run_finding(
    *,
    confidence: float,
    severity: Severity = Severity.HIGH,
) -> ThreatIntelFinding:
    return build_finding(
        finding_id="TI-IOC_RUN-IP_10.0.1.42-001-d3_run_aaaaaaaa",
        finding_type=ThreatIntelFindingType.IOC_MATCH_RUNTIME,
        severity=severity,
        title="x",
        description="y",
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
        evidence={"ioc_entry": {"confidence": confidence}},
    )


def _technique_finding() -> ThreatIntelFinding:
    return build_finding(
        finding_id="TI-TECHNIQUE-T1059-001-d3_run_aaaaaaaa",
        finding_type=ThreatIntelFindingType.ATTACK_TECHNIQUE_OBSERVED,
        severity=Severity.LOW,
        title="x",
        description="y",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={"technique_id": "T1059"},
    )


# ---------------------------------------------------------------------------
# score_severity — pure function
# ---------------------------------------------------------------------------


def test_cve_kev_is_critical_regardless_of_evidence() -> None:
    assert score_severity(ThreatIntelFindingType.CVE_IN_KEV_CATALOG, {}) == Severity.CRITICAL


def test_attack_technique_is_medium() -> None:
    assert score_severity(ThreatIntelFindingType.ATTACK_TECHNIQUE_OBSERVED, {}) == Severity.MEDIUM


def test_ioc_net_high_floor_inclusive() -> None:
    """confidence == 0.8 -> HIGH (inclusive lower bound)."""
    assert (
        score_severity(
            ThreatIntelFindingType.IOC_MATCH_NETWORK,
            {"ioc_entry": {"confidence": 0.8}},
        )
        == Severity.HIGH
    )


def test_ioc_net_medium_floor_inclusive() -> None:
    """confidence == 0.5 -> MEDIUM."""
    assert (
        score_severity(
            ThreatIntelFindingType.IOC_MATCH_NETWORK,
            {"ioc_entry": {"confidence": 0.5}},
        )
        == Severity.MEDIUM
    )


def test_ioc_net_below_medium_is_low() -> None:
    """confidence < 0.5 -> LOW."""
    assert (
        score_severity(
            ThreatIntelFindingType.IOC_MATCH_NETWORK,
            {"ioc_entry": {"confidence": 0.49}},
        )
        == Severity.LOW
    )


def test_ioc_run_obeys_same_confidence_table() -> None:
    high = {"ioc_entry": {"confidence": 0.95}}
    medium = {"ioc_entry": {"confidence": 0.55}}
    low = {"ioc_entry": {"confidence": 0.1}}
    assert score_severity(ThreatIntelFindingType.IOC_MATCH_RUNTIME, high) == Severity.HIGH
    assert score_severity(ThreatIntelFindingType.IOC_MATCH_RUNTIME, medium) == Severity.MEDIUM
    assert score_severity(ThreatIntelFindingType.IOC_MATCH_RUNTIME, low) == Severity.LOW


def test_ioc_match_with_missing_confidence_collapses_to_low() -> None:
    """Conservative default when ioc_entry is missing / malformed."""
    assert score_severity(ThreatIntelFindingType.IOC_MATCH_NETWORK, {}) == Severity.LOW
    assert (
        score_severity(ThreatIntelFindingType.IOC_MATCH_NETWORK, {"ioc_entry": "garbage"})
        == Severity.LOW
    )
    assert (
        score_severity(
            ThreatIntelFindingType.IOC_MATCH_NETWORK,
            {"ioc_entry": {"confidence": "not-a-number"}},
        )
        == Severity.LOW
    )


# ---------------------------------------------------------------------------
# score_findings — batch re-stamp semantics
# ---------------------------------------------------------------------------


def test_score_findings_passes_through_when_severity_already_canonical() -> None:
    cve = _cve_kev_finding(severity=Severity.CRITICAL)
    out = score_findings([cve])
    assert out[0] is cve  # identity preserved when no re-stamp needed


def test_score_findings_restamps_cve_kev_when_below_critical() -> None:
    """Even if an upstream correlator emits CVE_KEV at HIGH, the scorer
    re-stamps to CRITICAL."""
    cve = _cve_kev_finding(severity=Severity.HIGH)
    out = score_findings([cve])
    assert len(out) == 1
    assert out[0].severity == Severity.CRITICAL
    # finding_id (and the rest of the payload) is preserved.
    assert out[0].finding_id == cve.finding_id


def test_score_findings_restamps_ioc_net_to_medium_when_correlator_mis_emitted_high() -> None:
    """An IOC NET finding mistakenly emitted at HIGH despite confidence=0.6
    gets re-stamped to MEDIUM."""
    ioc = _ioc_net_finding(confidence=0.6, severity=Severity.HIGH)
    out = score_findings([ioc])
    assert out[0].severity == Severity.MEDIUM


def test_score_findings_preserves_envelope_after_restamp() -> None:
    """The envelope (correlation_id, tenant_id, ...) must survive re-stamping."""
    ioc = _ioc_net_finding(confidence=0.3, severity=Severity.HIGH)
    out = score_findings([ioc])
    restamped = out[0]
    assert restamped.severity == Severity.LOW
    assert restamped.envelope.tenant_id == "acme"
    assert restamped.envelope.correlation_id == "00000000-0000-0000-0000-00000000d8d8"


def test_score_findings_preserves_severity_id_round_trip() -> None:
    """The OCSF severity_id integer must match the new severity string after
    re-stamping (HIGH=4, MEDIUM=3, LOW=2, CRITICAL=5)."""
    findings = [
        _cve_kev_finding(severity=Severity.HIGH),
        _ioc_net_finding(confidence=0.95, severity=Severity.LOW),
        _ioc_run_finding(confidence=0.6, severity=Severity.LOW),
    ]
    out = score_findings(findings)
    severity_ids = [int(f.to_dict()["severity_id"]) for f in out]
    severity_strings = [str(f.to_dict()["severity"]).lower() for f in out]
    assert severity_ids == [5, 4, 3]
    assert severity_strings == ["critical", "high", "medium"]


def test_score_findings_batch_mixed_types() -> None:
    """A merged tuple of all four correlator types gets correct canonical severities."""
    findings = [
        _cve_kev_finding(severity=Severity.LOW),
        _ioc_net_finding(confidence=0.9, severity=Severity.LOW),
        _ioc_run_finding(confidence=0.55, severity=Severity.LOW),
        _technique_finding(),
    ]
    out = score_findings(findings)
    severities = [f.severity for f in out]
    assert severities == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.MEDIUM,
    ]


def test_score_findings_handles_unknown_finding_type_gracefully() -> None:
    """An OCSF payload whose finding_info.types[0] isn't a known
    ThreatIntelFindingType is returned unchanged (defensive)."""
    cve = _cve_kev_finding(severity=Severity.CRITICAL)
    payload: dict[str, Any] = cve.to_dict()
    payload["finding_info"] = {**payload["finding_info"], "types": ["unknown_thing"]}
    # We bypass the wrapper's normal validation by constructing directly
    # against a payload whose finding-id still matches the threat-intel
    # regex (CVE_KEV finding id). The scorer should leave it alone.
    finding = ThreatIntelFinding(payload)
    out = score_findings([finding])
    assert out[0] is finding


def test_score_findings_handles_empty_input() -> None:
    assert score_findings([]) == ()
