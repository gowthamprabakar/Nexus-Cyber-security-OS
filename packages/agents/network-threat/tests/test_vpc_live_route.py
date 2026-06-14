"""network-threat Phase C SS4 — guarded live VPC-flow route + read_vpc_flow_live registration.

Proves the v0.2 live CloudWatch VPC-flow poller is now (a) registered so it dispatches through
the charter proxy and (b) reachable from run() behind a guarded ``vpc_flow_log_group`` flag.
The realtime Suricata/Zeek subscribers are continuous infra and intentionally stay unregistered.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from network_threat import agent as agent_mod
from network_threat.agent import build_registry, run
from network_threat.schemas import FlowRecord


def _live_contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J0000000000000000000NETT",
        source_agent="supervisor",
        target_agent="network_threat",
        customer_id="cust_test",
        task="Live network threat scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10
        ),
        permitted_tools=[
            "read_suricata_alerts",
            "read_vpc_flow_logs",
            "read_dns_logs",
            "read_vpc_flow_live",
        ],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path),
        persistent_root=str(tmp_path / "_persistent"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _flow() -> FlowRecord:
    now = datetime.now(UTC)
    return FlowRecord(
        src_ip="8.8.8.8",
        dst_ip="10.0.0.5",
        src_port=443,
        dst_port=51000,
        protocol=6,
        bytes_transferred=1200,
        packets=4,
        start_time=now,
        end_time=now,
        action="ACCEPT",
    )


def test_build_registry_includes_live_poller_not_subscribers() -> None:
    known = build_registry().known_tools()
    assert "read_vpc_flow_live" in known
    assert build_registry().cloud_calls("read_vpc_flow_live") == 1
    # The realtime streaming subscribers are continuous infra, NOT request/response tools.
    assert "suricata_realtime" not in known
    assert "zeek_realtime" not in known


@pytest.mark.asyncio
async def test_run_live_vpc_route_dispatches_poller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    async def _fake_live(*, log_group: str, **kwargs: object) -> tuple[FlowRecord, ...]:
        captured["log_group"] = log_group
        captured.update(kwargs)
        return (_flow(),)

    # build_registry() registers the module-global reference, so patching it here means the
    # charter dispatches the fake — proving run() routes the live source through the proxy.
    monkeypatch.setattr(agent_mod, "read_vpc_flow_live", _fake_live)

    report = await run(_live_contract(tmp_path), vpc_flow_log_group="/aws/vpc/flowlogs")

    assert captured["log_group"] == "/aws/vpc/flowlogs"
    assert (tmp_path / "findings.json").is_file()
    assert report.agent == "network_threat"


@pytest.mark.asyncio
async def test_live_route_mutually_exclusive_with_feed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        await run(
            _live_contract(tmp_path),
            vpc_flow_log_group="/aws/vpc/flowlogs",
            vpc_flow_feed=tmp_path / "flows.log",
        )


# ---------------------------------------------------------------------------
# A-1.4 — Suricata + Zeek-DNS realtime streams via bounded_drain
# ---------------------------------------------------------------------------


class _Stream:
    """A finite fake push stream (models a live socket for the ungated layer)."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        for e in self._events:
            yield e


_SURICATA_ALERT = {
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

_ZEEK_DNS = {"query": "example.com", "id.orig_h": "10.0.0.5", "qtype_name": "A"}


@pytest.mark.asyncio
async def test_run_suricata_stream_emits_finding(tmp_path: Path) -> None:
    """A-1.4: an injected Suricata stream drives a finding via bounded_drain."""
    report = await run(
        _live_contract(tmp_path),
        suricata_stream=_Stream([_SURICATA_ALERT]),
    )
    assert report.total >= 1
    assert (tmp_path / "findings.json").is_file()


@pytest.mark.asyncio
async def test_run_zeek_dns_stream_drains_cleanly(tmp_path: Path) -> None:
    """A-1.4: an injected Zeek stream drains DNS events (conn deferred) without error."""
    report = await run(
        _live_contract(tmp_path),
        zeek_stream=_Stream([_ZEEK_DNS]),
    )
    assert report.agent == "network_threat"
    assert (tmp_path / "findings.json").is_file()


@pytest.mark.asyncio
async def test_realtime_max_events_bounds_the_drain(tmp_path: Path) -> None:
    """A-1.4: realtime_max_events caps how many stream events are ingested."""
    alerts = [dict(_SURICATA_ALERT) for _ in range(5)]
    report = await run(
        _live_contract(tmp_path),
        suricata_stream=_Stream(alerts),
        realtime_max_events=2,
    )
    # 5 identical alerts dedupe to 1 finding; the bound capped ingestion at 2.
    assert report.total >= 1


@pytest.mark.asyncio
async def test_suricata_stream_mutually_exclusive_with_feed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        await run(
            _live_contract(tmp_path),
            suricata_stream=_Stream([_SURICATA_ALERT]),
            suricata_feed=tmp_path / "eve.json",
        )


@pytest.mark.asyncio
async def test_zeek_stream_mutually_exclusive_with_dns_feed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        await run(
            _live_contract(tmp_path),
            zeek_stream=_Stream([_ZEEK_DNS]),
            dns_feed=tmp_path / "dns.log",
        )
