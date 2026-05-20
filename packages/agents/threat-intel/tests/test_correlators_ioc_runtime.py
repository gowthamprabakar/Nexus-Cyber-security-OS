"""Tests — ``threat_intel.correlators.ioc_correlator_runtime`` (Task 9).

Builds in-memory D.3 ``findings.json`` fixtures using D.3's own
``build_finding`` (real wire shape) and asserts the emitted
``ThreatIntelFinding``s.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from runtime_threat.schemas import (
    AffectedHost,
    FindingType,
)
from runtime_threat.schemas import (
    Severity as RtSeverity,
)
from runtime_threat.schemas import (
    build_finding as build_rt_finding,
)
from shared.fabric.envelope import NexusEnvelope
from threat_intel.correlators.ioc_correlator_runtime import correlate_ioc_runtime
from threat_intel.correlators.ioc_index import build_ioc_index
from threat_intel.entities import IocEntity
from threat_intel.schemas import IocType, Severity, ThreatIntelFindingType


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


def _write_d3_findings(workspace: Path, payloads: list[dict[str, Any]]) -> None:
    report = {
        "agent": "runtime_threat",
        "agent_version": "0.1.0",
        "customer_id": "acme",
        "run_id": "run_1",
        "scan_started_at": "2026-05-21T00:00:00+00:00",
        "scan_completed_at": "2026-05-21T00:00:05+00:00",
        "findings": payloads,
    }
    (workspace / "findings.json").write_text(json.dumps(report), encoding="utf-8")


def _host(
    hostname: str = "ip-10-0-1-42",
    host_id: str = "abc123def456",
    *,
    ip: str = "10.0.1.42",
) -> AffectedHost:
    return AffectedHost(
        hostname=hostname,
        host_id=host_id,
        image_ref="nginx:1.27",
        namespace="production",
        ip_addresses=(ip,) if ip else (),
    )


def _d3_network_payload(
    *,
    finding_id: str = "RUNTIME-NETWORK-ABC123-001-egress",
    remote_ip: str = "203.0.113.55",
    host_ip: str = "10.0.1.42",
) -> dict[str, Any]:
    finding = build_rt_finding(
        finding_id=finding_id,
        finding_type=FindingType.NETWORK,
        severity=RtSeverity.HIGH,
        title="Outbound connection to external host",
        description="Container talked to a remote IP.",
        affected_hosts=[_host(ip=host_ip)],
        evidence={
            "remote_ip": remote_ip,
            "remote_port": 443,
            "direction": "outbound",
        },
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        rule_id="nx-egress-policy",
    )
    return finding.to_dict()


def _d3_file_payload(
    *,
    finding_id: str = "RUNTIME-FILE-ABC123-001-suspicious",
    file_path: str = "/var/lib/malware.bin",
    file_hash: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "file_path": file_path,
        "access_type": "write",
    }
    if file_hash:
        evidence["file_hash"] = file_hash
    finding = build_rt_finding(
        finding_id=finding_id,
        finding_type=FindingType.FILE,
        severity=RtSeverity.HIGH,
        title="Suspicious file write",
        description="Write to /tmp by privileged process.",
        affected_hosts=[_host()],
        evidence=evidence,
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        rule_id="nx-suspicious-file-write",
    )
    return finding.to_dict()


def _d3_process_payload(
    *,
    finding_id: str = "RUNTIME-PROCESS-ABC123-001-spawn",
    proc_hash: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "proc_cmdline": "/usr/bin/curl https://example.com",
        "proc_pid": 4242,
        "proc_user": "root",
        "parent_pid": 1,
    }
    if proc_hash:
        evidence["proc_hash"] = proc_hash
    finding = build_rt_finding(
        finding_id=finding_id,
        finding_type=FindingType.PROCESS,
        severity=RtSeverity.MEDIUM,
        title="Privileged process spawned curl",
        description="Container root invoked curl.",
        affected_hosts=[_host()],
        evidence=evidence,
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        rule_id="nx-shell-out",
    )
    return finding.to_dict()


# ---------------------------------------------------------------------------
# Skip-cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_returns_empty_when_workspace_is_none() -> None:
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=None,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_ioc_index_empty(tmp_path: Path) -> None:
    _write_d3_findings(tmp_path, [_d3_network_payload()])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index={},
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_findings_json_missing(tmp_path: Path) -> None:
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_findings_json_malformed(tmp_path: Path) -> None:
    (tmp_path / "findings.json").write_text("{nope", encoding="utf-8")
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


# ---------------------------------------------------------------------------
# IP matches (remote_ip / host ip)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_remote_ip_match_emits_high(tmp_path: Path) -> None:
    _write_d3_findings(tmp_path, [_d3_network_payload(remote_ip="203.0.113.55")])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55", confidence=0.95)]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == ThreatIntelFindingType.IOC_MATCH_RUNTIME.value


@pytest.mark.asyncio
async def test_host_ip_match(tmp_path: Path) -> None:
    """Host-side IP (affected_hosts[].ip[]) can also match the IOC index."""
    _write_d3_findings(tmp_path, [_d3_network_payload(host_ip="10.0.1.42")])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "10.0.1.42")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# File-hash + process-hash matches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_hash_match(tmp_path: Path) -> None:
    sha = "a" * 64
    _write_d3_findings(tmp_path, [_d3_file_payload(file_hash=sha)])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.FILE_HASH, sha)]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
    ev = findings[0].to_dict()["evidences"][0]
    assert ev["observable_match"] == {"type": "file_hash", "value": sha}


@pytest.mark.asyncio
async def test_process_hash_match(tmp_path: Path) -> None:
    sha = "b" * 64
    _write_d3_findings(tmp_path, [_d3_process_payload(proc_hash=sha)])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.FILE_HASH, sha)]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_no_hash_in_evidence_still_works_for_ip_only(tmp_path: Path) -> None:
    """A FILE finding with no file_hash key is silently fine -- the IP path
    can still match if the host's IP is in the index."""
    _write_d3_findings(tmp_path, [_d3_file_payload(file_hash=None)])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "10.0.1.42")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
    assert findings[0].to_dict()["evidences"][0]["observable_match"]["type"] == "ip"


# ---------------------------------------------------------------------------
# Severity selection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_medium_confidence_emits_medium(tmp_path: Path) -> None:
    _write_d3_findings(tmp_path, [_d3_network_payload(remote_ip="203.0.113.55")])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55", confidence=0.6)]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_low_confidence_emits_low(tmp_path: Path) -> None:
    _write_d3_findings(tmp_path, [_d3_network_payload(remote_ip="203.0.113.55")])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55", confidence=0.3)]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# Finding-id and resource shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finding_id_token_shape(tmp_path: Path) -> None:
    _write_d3_findings(tmp_path, [_d3_network_payload(remote_ip="203.0.113.55")])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    fid = findings[0].finding_id
    assert fid.startswith("TI-IOC_RUN-IP_203.0.113.55-001-")
    assert "d3_run_" in fid


@pytest.mark.asyncio
async def test_resource_is_workload_host(tmp_path: Path) -> None:
    _write_d3_findings(tmp_path, [_d3_network_payload()])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope("contoso"),
    )
    resource = findings[0].resources[0]
    assert resource["type"] == "workload_host"
    assert resource["uid"] == "host:ip-10-0-1-42"
    assert resource["owner"]["account_uid"] == "contoso"


# ---------------------------------------------------------------------------
# Multi-finding + skip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sequence_increments_across_findings(tmp_path: Path) -> None:
    _write_d3_findings(
        tmp_path,
        [
            _d3_network_payload(
                finding_id="RUNTIME-NETWORK-ABC123-001-egress",
                remote_ip="203.0.113.55",
            ),
            _d3_network_payload(
                finding_id="RUNTIME-NETWORK-DEF456-001-egress",
                remote_ip="198.51.100.42",
            ),
        ],
    )
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index(
            [_ioc(IocType.IP, "203.0.113.55"), _ioc(IocType.IP, "198.51.100.42")]
        ),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    seqs = [f.finding_id.split("-")[3] for f in findings]
    assert seqs == ["001", "002"]


@pytest.mark.asyncio
async def test_non_2004_entries_skipped(tmp_path: Path) -> None:
    net = _d3_network_payload()
    other = {**net, "class_uid": 2003}
    _write_d3_findings(tmp_path, [other, net])
    findings = await correlate_ioc_runtime(
        runtime_threat_workspace=tmp_path,
        ioc_index=build_ioc_index([_ioc(IocType.IP, "203.0.113.55")]),
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
