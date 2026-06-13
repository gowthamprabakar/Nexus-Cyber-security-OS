"""Phase C SS2 — D.4 run-flow IP-block wiring makes assert_block_authorized load-bearing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from network_threat.actions.temporary_ip_block import (
    MAX_TTL_SECONDS,
    TemporaryIpBlock,
    build_temporary_ip_blocks,
    temporary_ip_blocks_to_json,
)
from network_threat.schemas import (
    AffectedNetwork,
    FindingType,
    Severity,
    build_finding,
    finding_type_token,
)
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 6, 13, tzinfo=UTC)


def _env() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="network_threat@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="inv_1",
    )


def _finding(
    *,
    src_ip: str,
    severity: Severity,
    seq: str = "001",
    evidence: dict[str, Any] | None = None,
) -> Any:
    ft = FindingType.SURICATA
    return build_finding(
        finding_id=f"NETWORK-{finding_type_token(ft)}-100005-{seq}-malware",
        finding_type=ft,
        severity=severity,
        title="malware c2",
        description="x",
        affected_networks=[AffectedNetwork(src_ip=src_ip, dst_ip="8.8.4.4")],
        evidence=evidence or {"signature": "c2"},
        detected_at=NOW,
        envelope=_env(),
        detector_id="suricata@0.1.0",
    )


def test_public_ip_high_severity_emits_block() -> None:
    blocks = build_temporary_ip_blocks(
        [_finding(src_ip="8.8.8.8", severity=Severity.CRITICAL)], requested_at=NOW
    )
    assert len(blocks) == 1
    b = blocks[0]
    assert isinstance(b, TemporaryIpBlock)
    assert b.target_ip == "8.8.8.8"
    assert b.action_type == "temporary_ip_block"
    assert 0 < b.ttl_seconds <= MAX_TTL_SECONDS
    assert b.is_temporary


def test_private_source_ip_skipped_by_guard() -> None:
    # private src -> assert_block_authorized rejects -> skipped (WI-N10), guard authoritative.
    blocks = build_temporary_ip_blocks(
        [_finding(src_ip="10.0.0.5", severity=Severity.CRITICAL)], requested_at=NOW
    )
    assert blocks == []


def test_low_severity_skipped() -> None:
    blocks = build_temporary_ip_blocks(
        [_finding(src_ip="8.8.8.8", severity=Severity.MEDIUM)], requested_at=NOW
    )
    assert blocks == []


def test_dedup_same_ip_across_findings() -> None:
    findings = [
        _finding(src_ip="8.8.8.8", severity=Severity.HIGH, seq="001"),
        _finding(src_ip="8.8.8.8", severity=Severity.CRITICAL, seq="002"),
    ]
    blocks = build_temporary_ip_blocks(findings, requested_at=NOW)
    assert [b.target_ip for b in blocks] == ["8.8.8.8"]


def test_serialization() -> None:
    import json

    blocks = build_temporary_ip_blocks(
        [_finding(src_ip="8.8.8.8", severity=Severity.HIGH)], requested_at=NOW
    )
    payload = json.loads(temporary_ip_blocks_to_json(blocks))
    assert payload[0]["target_ip"] == "8.8.8.8"
    assert payload[0]["action_type"] == "temporary_ip_block"
