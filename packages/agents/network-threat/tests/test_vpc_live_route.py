"""network-threat Phase C SS4 — guarded live VPC-flow route + read_vpc_flow_live registration.

Proves the v0.2 live CloudWatch VPC-flow poller is now (a) registered so it dispatches through
the charter proxy and (b) reachable from run() behind a guarded ``vpc_flow_log_group`` flag.
The realtime Suricata/Zeek subscribers are continuous infra and intentionally stay unregistered.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

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
