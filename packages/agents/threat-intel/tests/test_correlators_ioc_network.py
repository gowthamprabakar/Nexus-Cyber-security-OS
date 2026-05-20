"""Tests — ``threat_intel.correlators.ioc_correlator_network`` (Task 8).

Builds in-memory D.4 ``findings.json`` fixtures using D.4's own
``build_finding`` (real wire shape), runs the correlator against a
constructed IOC index, and asserts the emitted ``ThreatIntelFinding``s.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from network_threat.schemas import (
    AffectedNetwork,
    FindingType,
)
from network_threat.schemas import (
    Severity as NetSeverity,
)
from network_threat.schemas import (
    build_finding as build_net_finding,
)
from shared.fabric.envelope import NexusEnvelope
from threat_intel.correlators.ioc_correlator_network import correlate_ioc_network
from threat_intel.correlators.ioc_index import build_ioc_index
from threat_intel.entities import IocEntity
from threat_intel.schemas import IocType, Severity, ThreatIntelFindingType

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


def _ioc(
    ioc_type: IocType,
    value: str,
    *,
    confidence: float = 0.9,
    source_feed: str = "abuse.ch",
) -> IocEntity:
    return IocEntity(
        ioc_type=ioc_type,
        value=value,
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 2, tzinfo=UTC),
        confidence=confidence,
        source_feed=source_feed,
    )


def _write_d4_findings(workspace: Path, payloads: list[dict[str, Any]]) -> None:
    report = {
        "agent": "network_threat",
        "agent_version": "0.1.0",
        "customer_id": "acme",
        "run_id": "run_1",
        "scan_started_at": "2026-05-21T00:00:00+00:00",
        "scan_completed_at": "2026-05-21T00:00:05+00:00",
        "findings": payloads,
    }
    (workspace / "findings.json").write_text(json.dumps(report), encoding="utf-8")


def _d4_beacon_payload(
    *,
    finding_id: str = "NETWORK-BEACON-10001042-001-periodic",
    src_ip: str = "10.0.1.42",
    dst_ip: str = "203.0.113.55",
) -> dict[str, Any]:
    finding = build_net_finding(
        finding_id=finding_id,
        finding_type=FindingType.BEACON,
        severity=NetSeverity.HIGH,
        title="Periodic beacon to external host",
        description="100 connections at 60s period.",
        affected_networks=[
            AffectedNetwork(src_ip=src_ip, dst_ip=dst_ip, src_cidr="10.0.1.0/24"),
        ],
        evidence={
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "period_seconds": 60.0,
            "variance_seconds": 1.5,
            "connection_count": 100,
        },
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        detector_id="beacon@0.1.0",
    )
    return finding.to_dict()


def _d4_dga_payload(
    *,
    finding_id: str = "NETWORK-DGA-10001042-001-entropy",
    src_ip: str = "10.0.1.42",
    query_name: str = "kjhasdfkjhasd.example",
) -> dict[str, Any]:
    finding = build_net_finding(
        finding_id=finding_id,
        finding_type=FindingType.DGA,
        severity=NetSeverity.MEDIUM,
        title="DGA-like query",
        description="High entropy domain",
        affected_networks=[AffectedNetwork(src_ip=src_ip, dst_ip="198.51.100.1")],
        evidence={
            "src_ip": src_ip,
            "query_name": query_name,
            "entropy": 4.2,
            "bigram_score": 0.01,
        },
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        detector_id="dga@0.1.0",
    )
    return finding.to_dict()


def _d4_suricata_payload(
    *,
    finding_id: str = "NETWORK-SURICATA-10001042-001-sig",
    src_ip: str = "10.0.1.42",
    dst_ip: str = "203.0.113.55",
    signature: str = "ET EXPLOIT Possible CVE-2021-44228 exploit attempt",
) -> dict[str, Any]:
    finding = build_net_finding(
        finding_id=finding_id,
        finding_type=FindingType.SURICATA,
        severity=NetSeverity.HIGH,
        title="Suricata alert",
        description=signature,
        affected_networks=[AffectedNetwork(src_ip=src_ip, dst_ip=dst_ip)],
        evidence={
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "signature_id": 2034567,
            "signature": signature,
        },
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        detector_id="suricata:2024-001",
    )
    return finding.to_dict()


# ---------------------------------------------------------------------------
# Skip-cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_returns_empty_when_workspace_is_none() -> None:
    findings = await correlate_ioc_network(
        network_threat_workspace=None,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_ioc_index_empty(tmp_path: Path) -> None:
    _write_d4_findings(tmp_path, [_d4_beacon_payload()])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index={},
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_findings_json_missing(tmp_path: Path) -> None:
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_findings_json_malformed(tmp_path: Path) -> None:
    (tmp_path / "findings.json").write_text("{nope", encoding="utf-8")
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_no_observable_matches(tmp_path: Path) -> None:
    _write_d4_findings(tmp_path, [_d4_beacon_payload()])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "198.51.100.99")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


# ---------------------------------------------------------------------------
# IP matches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dst_ip_match_emits_high_severity_when_confidence_high(tmp_path: Path) -> None:
    _write_d4_findings(tmp_path, [_d4_beacon_payload(dst_ip="203.0.113.55")])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55", confidence=0.95)]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == ThreatIntelFindingType.IOC_MATCH_NETWORK.value
    assert finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_medium_confidence_emits_medium_severity(tmp_path: Path) -> None:
    _write_d4_findings(tmp_path, [_d4_beacon_payload(dst_ip="203.0.113.55")])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55", confidence=0.6)]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_low_confidence_emits_low_severity(tmp_path: Path) -> None:
    _write_d4_findings(tmp_path, [_d4_beacon_payload(dst_ip="203.0.113.55")])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55", confidence=0.3)]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_src_and_dst_ip_in_same_finding_dedup_to_one_emit_per_value(
    tmp_path: Path,
) -> None:
    """If both src and dst IPs are in the index, that's 2 distinct IOC values
    but only 2 emits (one each), not 4 (avoiding double-emit via affected_networks
    AND evidence both contributing the same observable).
    """
    _write_d4_findings(tmp_path, [_d4_beacon_payload(src_ip="10.0.1.42", dst_ip="203.0.113.55")])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index(
            [
                _ioc(IocType.IP, "10.0.1.42"),
                _ioc(IocType.IP, "203.0.113.55"),
            ]
        ),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 2
    values = {f.to_dict()["evidences"][0]["observable_match"]["value"] for f in findings}
    assert values == {"10.0.1.42", "203.0.113.55"}


# ---------------------------------------------------------------------------
# Domain match (DGA)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dga_query_name_domain_match(tmp_path: Path) -> None:
    _write_d4_findings(tmp_path, [_d4_dga_payload(query_name="malicious.example")])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.DOMAIN, "malicious.example")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
    ev = findings[0].to_dict()["evidences"][0]
    assert ev["observable_match"] == {"type": "domain", "value": "malicious.example"}


# ---------------------------------------------------------------------------
# CVE-ID match (Suricata signature)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cve_id_in_suricata_signature_match(tmp_path: Path) -> None:
    _write_d4_findings(
        tmp_path,
        [_d4_suricata_payload(signature="ET EXPLOIT Possible CVE-2021-44228 exploit attempt")],
    )
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.CVE_ID, "CVE-2021-44228")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
    ev = findings[0].to_dict()["evidences"][0]
    assert ev["observable_match"] == {"type": "cve_id", "value": "CVE-2021-44228"}


@pytest.mark.asyncio
async def test_multiple_cve_ids_in_one_signature(tmp_path: Path) -> None:
    """Two CVEs in one signature -> two emits if both are in the index."""
    _write_d4_findings(
        tmp_path,
        [
            _d4_suricata_payload(
                signature="ET EXPLOIT CVE-2021-44228 / CVE-2024-12345 chained exploit"
            )
        ],
    )
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index(
            [_ioc(IocType.CVE_ID, "CVE-2021-44228"), _ioc(IocType.CVE_ID, "CVE-2024-12345")]
        ),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Finding-id and shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finding_id_carries_ioc_type_and_value_token(tmp_path: Path) -> None:
    _write_d4_findings(tmp_path, [_d4_beacon_payload(dst_ip="203.0.113.55")])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    fid = findings[0].finding_id
    assert fid.startswith("TI-IOC_NET-IP_203.0.113.55-001-")
    assert "d4_net_" in fid


@pytest.mark.asyncio
async def test_evidence_carries_ioc_entry_and_source_link(tmp_path: Path) -> None:
    _write_d4_findings(tmp_path, [_d4_beacon_payload()])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index(
            [_ioc(IocType.IP, "203.0.113.55", source_feed="my_feed", confidence=0.9)]
        ),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    ev = findings[0].to_dict()["evidences"][0]
    assert ev["ioc_entry"]["source_feed"] == "my_feed"
    assert ev["ioc_entry"]["confidence"] == 0.9
    assert ev["source_d4_finding_id"] == "NETWORK-BEACON-10001042-001-periodic"


@pytest.mark.asyncio
async def test_resource_synthesises_network_endpoint(tmp_path: Path) -> None:
    _write_d4_findings(tmp_path, [_d4_beacon_payload(src_ip="10.0.1.42", dst_ip="203.0.113.55")])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope("contoso"),
    )
    resources = findings[0].resources
    assert len(resources) == 1
    assert resources[0]["type"] == "network_endpoint"
    assert resources[0]["uid"] == "network:10.0.1.42:203.0.113.55"
    assert resources[0]["owner"]["account_uid"] == "contoso"


# ---------------------------------------------------------------------------
# Multi-finding / mixed workspace
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multiple_d4_findings_sequence_increments(tmp_path: Path) -> None:
    _write_d4_findings(
        tmp_path,
        [
            _d4_beacon_payload(
                finding_id="NETWORK-BEACON-10001042-001-periodic", dst_ip="203.0.113.55"
            ),
            _d4_beacon_payload(
                finding_id="NETWORK-BEACON-10001099-001-periodic", dst_ip="198.51.100.42"
            ),
        ],
    )
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index(
            [
                _ioc(IocType.IP, "203.0.113.55"),
                _ioc(IocType.IP, "198.51.100.42"),
            ]
        ),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    # finding-id shape: TI-IOC_NET-<TYPE>_<TOKEN>-NNN-<context>.
    # split('-') -> ['TI', 'IOC_NET', '<TYPE>_<TOKEN>', 'NNN', '<context>']
    seqs = [f.finding_id.split("-")[3] for f in findings]
    assert seqs == ["001", "002"]


@pytest.mark.asyncio
async def test_non_2004_class_uid_entries_skipped(tmp_path: Path) -> None:
    beacon = _d4_beacon_payload()
    other = {**beacon, "class_uid": 2003}
    _write_d4_findings(tmp_path, [other, beacon])
    findings = await correlate_ioc_network(
        network_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
