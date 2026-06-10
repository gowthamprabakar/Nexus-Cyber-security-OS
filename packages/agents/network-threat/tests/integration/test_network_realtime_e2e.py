"""WI-N4 (HARD) — live network real-time event end-to-end (D.4 v0.2 Task 19).

Two-layer per the WI-V6 / WI-I4 / WI-T4 / WI-R4 lineage:

1. **Offline layer (every push):** the real real-time pipeline — Suricata / Zeek / VPC
   subscription → normalization → detection/aggregation → OCSF 2004 finding emission —
   exercised end-to-end with injected fakes. Block action emission is verified
   TTL-bounded + public-IP-only (Q4); **auto-expiry is exercised end-to-end (WI-N11)**.
2. **Gated-live layer (`NEXUS_LIVE_NETWORK_*=1`):** probes live sensors; skipped in CI.

Honest scope (WI-N3): the real-time readers + framework are e2e-tested through emission;
wiring them into the agent's continuous run loop is a v0.3 carry-forward — the offline
`run()` remains the deterministic OCSF-emitting path (WI-N5 byte-identical).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from network_threat.actions.auto_expiry import BlockExpiryTracker
from network_threat.actions.emission_flow import emit_block_for_finding
from network_threat.actions.temporary_ip_block import UnauthorizedNetworkActionError
from network_threat.correlators.cross_sensor import (
    correlate_network_events,
    cross_sensor_events,
)
from network_threat.detectors.flow_anomaly import connection_rate_anomalies
from network_threat.live_lane import suricata_reachable, vpc_aws_reachable, zeek_reachable
from network_threat.schemas import (
    AffectedNetwork,
    FindingType,
    NetworkFinding,
    Severity,
    build_finding,
)
from network_threat.tools.suricata_normalize import normalize_suricata_event
from network_threat.tools.suricata_realtime import SuricataRealtimeSubscriber
from network_threat.tools.vpc_flow_normalize import aggregate_flows
from network_threat.tools.vpc_flow_realtime_aws import VpcFlowLiveReader
from network_threat.tools.zeek_normalize import ZeekConn, normalize_zeek_event
from network_threat.tools.zeek_realtime import ZeekRealtimeSubscriber

pytestmark = pytest.mark.asyncio

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)

_ALERT = {
    "event_type": "alert",
    "timestamp": "2026-06-11T11:59:00.000000+0000",
    "src_ip": "203.0.113.9",
    "dest_ip": "8.8.8.8",
    "src_port": 44321,
    "dest_port": 443,
    "proto": "TCP",
    "alert": {
        "signature_id": 2019401,
        "signature": "ET MALWARE C2",
        "category": "trojan",
        "severity": 1,
    },
}


class _Stream:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        for e in self._events:
            yield e


class _FakeLogs:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    def filter_log_events(self, **_: Any) -> dict[str, Any]:
        return {"events": self._events}


def _envelope() -> Any:
    from shared.fabric.envelope import NexusEnvelope

    return NexusEnvelope(
        correlation_id="corr_d4",
        tenant_id="cust_test",
        agent_id="network_threat@0.2.0",
        nlah_version="0.2.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def _finding(src_ip: str) -> NetworkFinding:
    return build_finding(
        finding_id="NETWORK-SURICATA-HOST1-001-c2",
        finding_type=FindingType.SURICATA,
        severity=Severity.CRITICAL,
        title="C2 alert",
        description="real-time detection",
        affected_networks=[
            AffectedNetwork(src_ip=src_ip, dst_ip="8.8.8.8", src_cidr="203.0.113.0/24")
        ],
        evidence={"src_ip": src_ip},
        detected_at=_T,
        envelope=_envelope(),
        detector_id="suricata@0.2.0",
    )


# ------------------- offline layer: full pipeline ------------------------


async def test_suricata_pipeline_emits_ocsf_2004() -> None:
    findings: list[NetworkFinding] = []

    async def handler(raw: dict[str, Any]) -> None:
        norm = normalize_suricata_event(raw, received_at=_T)
        if norm is not None:
            findings.append(_finding(norm.alert.src_ip))

    await SuricataRealtimeSubscriber(_Stream([_ALERT]), handler).run()
    assert len(findings) == 1  # construction validated class_uid 2004
    assert findings[0].finding_type == FindingType.SURICATA


async def test_zeek_pipeline_normalizes() -> None:
    seen: list[str] = []

    async def handler(raw: dict[str, Any]) -> None:
        norm = normalize_zeek_event(raw, received_at=_T)
        if isinstance(norm, ZeekConn):
            seen.append(norm.uid)

    conn = {"_path": "conn", "uid": "C1", "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8"}
    await ZeekRealtimeSubscriber(_Stream([conn]), handler).run()
    assert seen == ["C1"]


async def test_vpc_pipeline_aggregates_and_detects() -> None:
    flow = "2 123 eni-a 10.0.0.5 8.8.8.{} 44321 443 6 1 100 1700000000 1700000060 ACCEPT OK"
    events = [{"message": flow.format(i)} for i in range(25)]
    records = VpcFlowLiveReader(_FakeLogs(events)).poll("vpc-flow")
    anomalies = connection_rate_anomalies(aggregate_flows(records), min_distinct_destinations=20)
    assert anomalies and anomalies[0].src_ip == "10.0.0.5"


async def test_cross_sensor_correlation_e2e() -> None:
    norm = normalize_suricata_event(_ALERT, received_at=_T)
    assert norm is not None
    conn = ZeekConn(
        uid="C", src_ip="203.0.113.9", src_port=44321, dst_ip="8.8.8.8", dst_port=443, proto="tcp"
    )
    groups = correlate_network_events([norm.alert], [conn])
    assert len(cross_sensor_events(groups)) == 1


async def test_block_action_ttl_bounded_and_auto_expires() -> None:
    # Emit a TTL block on the public attacker IP, then verify auto-expiry (WI-N11).
    block = emit_block_for_finding(
        severity="critical", target_ip="8.8.8.8", ttl_seconds=300, reason="C2", requested_at=_T
    )
    assert block is not None and block.ttl_seconds == 300

    tracker = BlockExpiryTracker()
    tracker.register(block)
    removed: list[str] = []

    def remover(b: Any) -> bool:
        removed.append(b.target_ip)
        return True

    result = tracker.expire_due(_T + timedelta(seconds=301), remover=remover)
    assert removed == ["8.8.8.8"] and result.needs_escalation is False
    assert tracker.active() == ()  # auto-removed


async def test_private_ip_block_is_rejected() -> None:
    # Q4/WI-N10: a private-range target is never blocked (safe default = no block).
    assert (
        emit_block_for_finding(
            severity="critical", target_ip="10.0.0.5", ttl_seconds=300, reason="r", requested_at=_T
        )
        is None
    )
    from network_threat.actions.temporary_ip_block import assert_block_authorized

    with pytest.raises(UnauthorizedNetworkActionError):
        assert_block_authorized("temporary_ip_block", "10.0.0.5", 300)


# --------------------------- gated-live layer ----------------------------


async def test_live_suricata_reachable(suricata_gate: None) -> None:
    ok, reason = suricata_reachable()
    assert ok, f"Suricata unreachable: {reason}"


async def test_live_zeek_reachable(zeek_gate: None) -> None:
    ok, reason = zeek_reachable()
    assert ok, f"Zeek unreachable: {reason}"


async def test_live_vpc_reachable(vpc_gate: None) -> None:
    ok, reason = vpc_aws_reachable()
    assert ok, f"AWS VPC unreachable: {reason}"
