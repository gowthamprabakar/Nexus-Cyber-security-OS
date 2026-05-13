"""Unit tests for the Network Threat Agent driver.

All three reader tools are mocked at the agent module's import level;
the test surface is the agent's wiring of charter + readers + detectors
+ enrichment + summarizer, not the readers' parsing behaviour
(those have their own test files).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from network_threat import agent as agent_mod
from network_threat.agent import build_registry, run
from network_threat.schemas import (
    DnsEvent,
    DnsEventKind,
    FlowRecord,
    SuricataAlert,
    SuricataAlertSeverity,
)

NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="network_threat",
        customer_id="cust_test",
        task="Network threat scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["read_suricata_alerts", "read_vpc_flow_logs", "read_dns_logs"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _flow(
    *,
    src: str = "10.0.0.5",
    dst: str = "203.0.113.5",
    dst_port: int = 443,
    start: datetime | None = None,
    spacing_seconds: float = 0.1,
    index: int = 0,
) -> FlowRecord:
    start = start or NOW
    t = start + timedelta(seconds=index * spacing_seconds)
    return FlowRecord(
        src_ip=src,
        dst_ip=dst,
        src_port=49152,
        dst_port=dst_port,
        protocol=6,
        bytes_transferred=100,
        packets=1,
        start_time=t,
        end_time=t + timedelta(seconds=0.5),
        action="ACCEPT",
    )


def _dns_event(qname: str, src: str = "10.0.0.5") -> DnsEvent:
    return DnsEvent(
        timestamp=NOW,
        kind=DnsEventKind.QUERY,
        query_name=qname,
        query_type="A",
        src_ip=src,
    )


def _suricata(
    *,
    sig_id: int = 2001234,
    signature: str = "ET MALWARE Suspicious TLS",
    severity: SuricataAlertSeverity = SuricataAlertSeverity.HIGH,
) -> SuricataAlert:
    return SuricataAlert(
        timestamp=NOW,
        src_ip="203.0.113.5",
        dst_ip="10.0.1.42",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        signature_id=sig_id,
        signature=signature,
        severity=severity,
    )


def _patch_suricata(monkeypatch: pytest.MonkeyPatch, alerts: list[SuricataAlert]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[SuricataAlert, ...]:
        return tuple(alerts)

    monkeypatch.setattr(agent_mod, "read_suricata_alerts", fake)


def _patch_vpc_flow(monkeypatch: pytest.MonkeyPatch, flows: list[FlowRecord]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[FlowRecord, ...]:
        return tuple(flows)

    monkeypatch.setattr(agent_mod, "read_vpc_flow_logs", fake)


def _patch_dns(monkeypatch: pytest.MonkeyPatch, events: list[DnsEvent]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[DnsEvent, ...]:
        return tuple(events)

    monkeypatch.setattr(agent_mod, "read_dns_logs", fake)


# ---------------------------- registry -----------------------------------


def test_build_registry_includes_three_readers() -> None:
    reg = build_registry()
    known = reg.known_tools()
    assert "read_suricata_alerts" in known
    assert "read_vpc_flow_logs" in known
    assert "read_dns_logs" in known


# ---------------------------- empty path ---------------------------------


@pytest.mark.asyncio
async def test_run_with_no_feeds_yields_empty_report(tmp_path: Path) -> None:
    """All three feeds unset → agent emits empty findings and clean outputs."""
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "report.md").is_file()


@pytest.mark.asyncio
async def test_empty_findings_json_is_valid(tmp_path: Path) -> None:
    await run(_contract(tmp_path))
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "network_threat"
    assert payload["customer_id"] == "cust_test"
    assert payload["findings"] == []


# ---------------------------- per-feed happy paths -----------------------


@pytest.mark.asyncio
async def test_vpc_flow_with_port_scan_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """50 distinct ports from one src in 60s → one PORT_SCAN finding."""
    flows = [_flow(dst_port=1024 + i, index=i) for i in range(50)]
    _patch_vpc_flow(monkeypatch, flows)
    feed = tmp_path / "flow.log"
    feed.write_text("placeholder")  # readers are mocked but the path must exist

    report = await run(_contract(tmp_path), vpc_flow_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    finding = payload["findings"][0]
    assert finding["finding_info"]["types"][0] == "network_port_scan"
    assert finding["class_uid"] == 2004


@pytest.mark.asyncio
async def test_vpc_flow_with_beacon_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """10 periodic flows to one dst:port → one BEACON finding."""
    flows = [_flow(spacing_seconds=60.0, index=i) for i in range(10)]
    _patch_vpc_flow(monkeypatch, flows)
    feed = tmp_path / "flow.log"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), vpc_flow_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    # Either 1 BEACON, or 1 BEACON + 1 PORT_SCAN if all 10 hit the same port.
    types = {f["finding_info"]["types"][0] for f in payload["findings"]}
    assert "network_beacon" in types
    assert report.total >= 1


@pytest.mark.asyncio
async def test_dns_with_dga_emits_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_dns(monkeypatch, [_dns_event("xkfqpzwvxghmpls.tld")])
    feed = tmp_path / "dns.log"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), dns_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    assert payload["findings"][0]["finding_info"]["types"][0] == "network_dga"


@pytest.mark.asyncio
async def test_suricata_alerts_lift_to_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_suricata(monkeypatch, [_suricata()])
    feed = tmp_path / "eve.json"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), suricata_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    finding = payload["findings"][0]
    assert finding["finding_info"]["types"][0] == "network_suricata"
    # Severity HIGH (Suricata 1) survives the lift.
    assert finding["severity"] == "High"


# ---------------------------- multi-feed ---------------------------------


@pytest.mark.asyncio
async def test_three_feeds_concurrent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """All three feeds running in parallel should emit findings from each."""
    _patch_suricata(monkeypatch, [_suricata()])
    _patch_vpc_flow(monkeypatch, [_flow(dst_port=1024 + i, index=i) for i in range(50)])
    _patch_dns(monkeypatch, [_dns_event("xkfqpzwvxghmpls.tld")])

    s = tmp_path / "s.json"
    v = tmp_path / "v.log"
    d = tmp_path / "d.log"
    for p in (s, v, d):
        p.write_text("placeholder")

    report = await run(
        _contract(tmp_path),
        suricata_feed=s,
        vpc_flow_feed=v,
        dns_feed=d,
    )
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in payload["findings"]}
    # Suricata + port_scan + DGA expected; beacon may also appear if jitter is 0.
    assert {"network_suricata", "network_port_scan", "network_dga"}.issubset(types)
    assert report.total >= 3


# ---------------------------- intel enrichment uplift --------------------


@pytest.mark.asyncio
async def test_beacon_to_tor_exit_severity_uplifts_to_critical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Periodic beacon to a Tor-exit-range IP → ENRICH bumps severity to CRITICAL."""
    flows = [
        _flow(
            dst="185.220.101.42",  # in 185.220.101.0/24 (Tor exit)
            spacing_seconds=60.0,
            index=i,
        )
        for i in range(20)
    ]
    _patch_vpc_flow(monkeypatch, flows)
    feed = tmp_path / "flow.log"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), vpc_flow_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    beacons = [f for f in payload["findings"] if f["finding_info"]["types"][0] == "network_beacon"]
    assert len(beacons) >= 1
    # Base severity HIGH (count=20, low CoV); intel uplift → CRITICAL.
    assert beacons[0]["severity"] == "Critical"
    # Intel annotation present.
    assert "intel" in beacons[0]["evidences"][0]


# ---------------------------- output files -------------------------------


@pytest.mark.asyncio
async def test_outputs_have_expected_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_dns(monkeypatch, [_dns_event("xkfqpzwvxghmpls.tld")])
    feed = tmp_path / "dns.log"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), dns_feed=feed)

    # findings.json
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "network_threat"
    assert payload["findings"][0]["class_uid"] == 2004
    # report.md
    report_md = (tmp_path / "ws" / "report.md").read_text()
    assert "# Network Threat Scan" in report_md
    assert "## DGA domains" in report_md  # pinned section


# ---------------------------- dedup pass ---------------------------------


@pytest.mark.asyncio
async def test_dedupe_collapses_duplicate_detections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the same DGA query appears twice from the same src in the same 5min bucket,
    only one finding is emitted (dedupe by composite key from Q6).
    """
    _patch_dns(
        monkeypatch,
        [_dns_event("xkfqpzwvxghmpls.tld"), _dns_event("xkfqpzwvxghmpls.tld")],
    )
    feed = tmp_path / "dns.log"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), dns_feed=feed)
    # detect_dga itself deduplicates; agent's dedup pass is the second-line defence.
    assert report.total == 1


# ---------------------------- audit chain --------------------------------


@pytest.mark.asyncio
async def test_audit_chain_emitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Per F.1: every run emits a hash-chained audit.jsonl in the workspace."""
    _patch_dns(monkeypatch, [_dns_event("xkfqpzwvxghmpls.tld")])
    feed = tmp_path / "dns.log"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), dns_feed=feed)
    audit_path = tmp_path / "ws" / "audit.jsonl"
    assert audit_path.is_file()
    lines = [ln for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert len(lines) >= 1
